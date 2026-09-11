"""In-memory fallback path for backend.redis (no Redis in test env)."""

import time

import pytest

from backend import redis as redis_mod


@pytest.fixture(autouse=True)
def _reset_redis_state():
    """Reset module-level globals so each test starts from a clean slate."""
    redis_mod._checked = False
    redis_mod._available = False
    redis_mod._client = None
    redis_mod._rate_buckets.clear()
    redis_mod._lockout.clear()
    redis_mod._account_lockout.clear()
    yield
    redis_mod._checked = False
    redis_mod._available = False
    redis_mod._client = None
    redis_mod._rate_buckets.clear()
    redis_mod._lockout.clear()
    redis_mod._account_lockout.clear()


# ── rate_increment ─────────────────────────────────────────────────────────


def test_rate_increment_basic():
    count, remaining = redis_mod.rate_increment("test:rate:1", 60)
    assert count == 1
    assert remaining > 0


def test_rate_increment_within_window():
    for i in range(1, 5):
        count, _ = redis_mod.rate_increment("test:rate:win", 60)
    assert count == 4


def test_rate_increment_window_expiry():
    count, _ = redis_mod.rate_increment("test:rate:exp", 1)
    assert count == 1

    redis_mod._rate_buckets["test:rate:exp"] = (time.monotonic() - 2, 5)
    count, remaining = redis_mod.rate_increment("test:rate:exp", 1)
    assert count == 1
    assert remaining > 0


# ── rate_cleanup ────────────────────────────────────────────────────────────


def test_rate_cleanup_no_op_when_under_limit():
    redis_mod._rate_buckets["a"] = (time.monotonic(), 1)
    redis_mod.rate_cleanup(max_entries=10)
    assert "a" in redis_mod._rate_buckets


def test_rate_cleanup_clears_when_over_limit():
    for i in range(12):
        redis_mod._rate_buckets[f"k{i}"] = (time.monotonic(), 1)
    redis_mod.rate_cleanup(max_entries=10)
    assert len(redis_mod._rate_buckets) == 0


# ── lockout_check ───────────────────────────────────────────────────────────


def test_lockout_check_not_locked_initially():
    is_locked, retry = redis_mod.lockout_check("user1", max_attempts=5, window_seconds=300)
    assert is_locked is False
    assert retry == 0


def test_lockout_check_locked_after_max_attempts():
    for _ in range(5):
        redis_mod.lockout_record("user2")
    is_locked, retry = redis_mod.lockout_check("user2", max_attempts=5, window_seconds=300)
    assert is_locked is True
    assert retry > 0


def test_lockout_clear_resets():
    for _ in range(3):
        redis_mod.lockout_record("user3")
    redis_mod.lockout_clear("user3")
    is_locked, _ = redis_mod.lockout_check("user3", max_attempts=2, window_seconds=300)
    assert is_locked is False


def test_lockout_record_adds_failure():
    redis_mod.lockout_record("rec1")
    redis_mod.lockout_record("rec1")
    assert len(redis_mod._lockout["rec1"]) == 2


# ── per-account lockout ────────────────────────────────────────────────────


def test_lockout_check_account_not_locked_initially():
    is_locked, retry = redis_mod.lockout_check_account(
        "alice", max_attempts=3, window_seconds=300
    )
    assert is_locked is False
    assert retry == 0


def test_lockout_check_account_locked():
    for _ in range(3):
        redis_mod.lockout_record_account("bob")
    is_locked, retry = redis_mod.lockout_check_account(
        "bob", max_attempts=3, window_seconds=300
    )
    assert is_locked is True
    assert retry > 0


def test_lockout_clear_account():
    for _ in range(3):
        redis_mod.lockout_record_account("carol")
    redis_mod.lockout_clear_account("carol")
    is_locked, _ = redis_mod.lockout_check_account(
        "carol", max_attempts=2, window_seconds=300
    )
    assert is_locked is False


# ── is_available ────────────────────────────────────────────────────────────


def test_is_available_false_without_redis():
    assert redis_mod.is_available() is False
