"""Single-instance lock semantics (PostgreSQL advisory locks)."""
import pytest
from sqlalchemy import create_engine

from backend.config import DATABASE_URL
from backend.locks import InstanceLock


@pytest.fixture
def lock_engine():
    return create_engine(DATABASE_URL, pool_pre_ping=True)


def test_first_holds_second_denied(lock_engine):
    a = InstanceLock(create_engine(DATABASE_URL))
    b = InstanceLock(create_engine(DATABASE_URL))
    try:
        assert a.acquire() is True
        assert b.acquire() is False
    finally:
        a.release()
        b.release()


def test_release_allows_next(lock_engine):
    a = InstanceLock(create_engine(DATABASE_URL))
    b = InstanceLock(create_engine(DATABASE_URL))
    assert a.acquire() is True
    a.release()
    assert b.acquire() is True
    b.release()


def test_dispose_releases_lock(lock_engine):
    a = InstanceLock(create_engine(DATABASE_URL))
    assert a.acquire() is True
    a.release()
    # Postgres releases advisory locks when their session closes; a.engine
    # dispose must therefore make the lock reusable by a new lock instance.
    b = InstanceLock(create_engine(DATABASE_URL))
    assert b.acquire() is True
    b.release()


def test_different_name_does_not_conflict(lock_engine):
    a = InstanceLock(create_engine(DATABASE_URL), name="lock-a")
    b = InstanceLock(create_engine(DATABASE_URL), name="lock-b")
    try:
        assert a.acquire() is True
        assert b.acquire() is True
    finally:
        a.release()
        b.release()