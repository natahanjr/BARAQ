"""Single-instance lock semantics (SQLite lockfile; Postgres in live env)."""
import os

import pytest
from sqlalchemy import create_engine

from backend.locks import InstanceLock, _pid_is_alive


@pytest.fixture
def sqlite_db(tmp_path):
    path = tmp_path / "soc.db"
    return f"sqlite:///{path}", path


def test_first_holds_second_denied(sqlite_db):
    url, _ = sqlite_db
    a = InstanceLock(create_engine(url))
    b = InstanceLock(create_engine(url))
    try:
        assert a.acquire() is True
        assert b.acquire() is False
    finally:
        a.release()


def test_release_allows_next(sqlite_db):
    url, _ = sqlite_db
    a = InstanceLock(create_engine(url))
    b = InstanceLock(create_engine(url))
    assert a.acquire() is True
    a.release()
    assert b.acquire() is True
    b.release()


def test_stale_lock_is_stolen(sqlite_db):
    url, path = sqlite_db
    lock_path = path.with_suffix(".db.sentinel.lock")
    lock_path.parent.mkdir(exist_ok=True)
    lock_path.write_text(str(999_999_999))  # PID that cannot exist
    assert not _pid_is_alive(999_999_999)
    lock = InstanceLock(create_engine(url))
    assert lock.acquire() is True
    lock.release()


def test_active_pid_not_stolen(sqlite_db):
    url, path = sqlite_db
    lock_path = path.with_suffix(".db.sentinel.lock")
    lock_path.parent.mkdir(exist_ok=True)
    lock_path.write_text(str(os.getpid()))
    assert _pid_is_alive(os.getpid())
    lock = InstanceLock(create_engine(url))
    assert lock.acquire() is False
    lock_path.unlink(missing_ok=True)


def test_sqlite_lockfile_removed_on_release(sqlite_db):
    url, path = sqlite_db
    lock = InstanceLock(create_engine(url))
    lock.acquire()
    lock_path = path.with_suffix(".db.sentinel.lock")
    assert lock_path.exists()
    lock.release()
    assert not lock_path.exists()