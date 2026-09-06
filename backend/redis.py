"""Shared Redis client with graceful fallback when Redis is unavailable.

Used by rate limiting, login lockout, and the distributed scheduler lock.
When BARAQ_REDIS_URL is empty or Redis is unreachable, all operations fall
back to in-memory dict equivalents so single-node dev still works.
"""

from __future__ import annotations

import logging
import time
from typing import Any

logger = logging.getLogger("baraq.redis")

_client: Any = None
_checked: bool = False
_available: bool = False


def _get_client():
    """Return a Redis client or None if Redis is not configured/reachable."""
    global _client, _checked, _available
    if _checked:
        return _client if _available else None
    _checked = True
    from backend.config import REDIS_URL

    if not REDIS_URL:
        return None
    try:
        import redis as _redis_mod

        _client = _redis_mod.Redis.from_url(
            REDIS_URL, decode_responses=True, socket_timeout=2, socket_connect_timeout=2
        )
        _client.ping()
        _available = True
        logger.info("Redis connected at %s", REDIS_URL.split("@")[-1])
        return _client
    except Exception as exc:
        _available = False
        logger.warning("Redis unavailable (%s), using in-memory fallback", exc)
        return None


def is_available() -> bool:
    """True if Redis is configured and reachable."""
    _get_client()
    return _available


# ---------------------------------------------------------------------------
# Rate limiting helpers (used by main.py api_gates middleware)
# ---------------------------------------------------------------------------

# In-memory fallback for rate limiting when Redis is absent.
_rate_buckets: dict[str, tuple[float, int]] = {}


def rate_increment(key: str, window_seconds: int) -> tuple[int, float]:
    """Increment counter for ``key`` within a sliding window.

    Returns (count_in_window, retry_after_seconds).
    """
    client = _get_client()
    if client is not None:
        pipe = client.pipeline()
        now = time.time()
        window_key = f"baraq:rate:{key}:{int(now // window_seconds)}"
        pipe.incr(window_key)
        pipe.expire(window_key, window_seconds * 2)
        results = pipe.execute()
        count = int(results[0])
        remaining = window_seconds - (now % window_seconds)
        return count, remaining
    else:
        now = time.monotonic()
        window_start, count = _rate_buckets.get(key, (now, 0))
        if now - window_start >= window_seconds:
            window_start, count = now, 0
        count += 1
        _rate_buckets[key] = (window_start, count)
        remaining = window_seconds - (now - window_start)
        return count, remaining


def rate_cleanup(max_entries: int = 10000) -> None:
    """Prune stale in-memory rate entries (no-op when using Redis)."""
    if _get_client() is not None:
        return
    if len(_rate_buckets) > max_entries:
        _rate_buckets.clear()


# ---------------------------------------------------------------------------
# Login lockout helpers (used by api/auth.py)
# ---------------------------------------------------------------------------

_lockout: dict[str, list[float]] = {}
_account_lockout: dict[str, list[float]] = {}


def lockout_check(key: str, max_attempts: int, window_seconds: int) -> tuple[bool, float]:
    """Check if ``key`` is locked out.

    Returns (is_locked, retry_after_seconds).
    """
    client = _get_client()
    if client is not None:
        rk = f"baraq:lockout:{key}"
        count = client.incr(rk)
        if count == 1:
            client.expire(rk, window_seconds)
        if count > max_attempts:
            ttl = client.ttl(rk)
            return True, float(ttl) if ttl > 0 else float(window_seconds)
        return False, 0
    else:
        now = time.monotonic()
        failures = [t for t in _lockout.get(key, []) if now - t < window_seconds]
        if len(failures) >= max_attempts:
            return True, float(window_seconds - (now - failures[0]))
        return False, 0


def lockout_record(key: str) -> None:
    """Record a failed attempt for in-memory lockout (no-op for Redis since
    lockout_check already increments)."""
    client = _get_client()
    if client is None:
        _lockout.setdefault(key, []).append(time.monotonic())
        if len(_lockout) > 10000:
            # Evict oldest 50% instead of clearing all
            items = sorted(_lockout.items(), key=lambda kv: kv[1][0] if kv[1] else 0)
            for k, _ in items[: len(items) // 2]:
                _lockout.pop(k, None)


def lockout_record_account(username: str) -> None:
    """Record a failed attempt for in-memory account lockout."""
    client = _get_client()
    if client is None:
        _account_lockout.setdefault(username.lower(), []).append(time.monotonic())
        if len(_account_lockout) > 10000:
            items = sorted(
                _account_lockout.items(), key=lambda kv: kv[1][0] if kv[1] else 0
            )
            for k, _ in items[: len(items) // 2]:
                _account_lockout.pop(k, None)


def lockout_clear(key: str) -> None:
    """Clear lockout for a key on successful login."""
    client = _get_client()
    if client is not None:
        client.delete(f"baraq:lockout:{key}")
    else:
        _lockout.pop(key, None)


def lockout_clear_account(username: str) -> None:
    """Clear account lockout on successful login."""
    client = _get_client()
    if client is not None:
        client.delete(f"baraq:lockout:acct:{username.lower()}")
    else:
        _account_lockout.pop(username.lower(), None)


def lockout_check_account(
    username: str, max_attempts: int, window_seconds: int
) -> tuple[bool, float]:
    """Per-account lockout check."""
    client = _get_client()
    if client is not None:
        rk = f"baraq:lockout:acct:{username.lower()}"
        count = client.incr(rk)
        if count == 1:
            client.expire(rk, window_seconds)
        if count > max_attempts:
            ttl = client.ttl(rk)
            return True, float(ttl) if ttl > 0 else float(window_seconds)
        return False, 0
    else:
        now = time.monotonic()
        failures = [
            t for t in _account_lockout.get(username.lower(), []) if now - t < window_seconds
        ]
        if len(failures) >= max_attempts:
            return True, float(window_seconds - (now - failures[0]))
        return False, 0
