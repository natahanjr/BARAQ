"""Single-instance guard: only one SentinelSOC process may run the scheduler.

Two uvicorn processes pointed at the same database would both collect,
detect, retrain and retain - duplicating alerts and racing the graph
build. ``acquire_instance_lock`` grabs a database-scoped advisory lock at
startup (PostgreSQL) or an exclusive lockfile (SQLite); a second process
fails to acquire it and skips the scheduler instead of corrupting state.

The lock is held for the process lifetime and released on shutdown, or
auto-released by the database/OS if the process dies.
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from sqlalchemy.engine import Engine

logger = logging.getLogger("sentinel.locks")

LOCK_NAME = "sentinel-soc-scheduler"


def _lock_path_for(sqlite_url: str) -> Path:
    """Lockfile sits next to the sqlite file so it is not cloned by backup."""
    raw = sqlite_url.replace("sqlite:///", "", 1)
    return Path(raw).with_suffix(".db.sentinel.lock")


def _pid_is_alive(pid: int) -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            process = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if not process:
                return False
            kernel32.CloseHandle(process)
            return True
        except Exception:  # noqa: BLE001
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class InstanceLock:
    """Database-scoped advisory lock held for the life of the process."""

    def __init__(self, engine: Engine, name: str = LOCK_NAME):
        self._engine = engine
        self._name = name
        self._pg_conn = None
        self._sqlite_path: Path | None = None
        self._held = False

    # -- acquisition --------------------------------------------------------
    def acquire(self) -> bool:
        url = str(self._engine.url)
        if url.startswith("sqlite"):
            return self._acquire_sqlite(url)
        return self._acquire_postgres()

    def _acquire_postgres(self) -> bool:
        try:
            conn = self._engine.connect()
            conn = conn.execution_options(isolation_level="AUTOCOMMIT")
            got = conn.execute(
                __import__("sqlalchemy").text(
                    "SELECT pg_try_advisory_lock(hashtext(:name))"
                ),
                {"name": self._name},
            ).scalar()
            if got:
                self._pg_conn = conn
                self._held = True
                logger.info("Instance lock acquired (postgres, %s)", self._name)
                return True
            conn.close()
            logger.warning(
                "Instance lock held by another process (postgres, %s); "
                "scheduler disabled on this instance",
                self._name,
            )
            return False
        except Exception:  # noqa: BLE001
            logger.exception("Postgres advisory lock failed; scheduler disabled")
            return False

    def _acquire_sqlite(self, url: str) -> bool:
        lock_path = _lock_path_for(url)
        try:
            fd = os.open(
                lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
            os.write(fd, str(os.getpid()).encode("ascii"))
            os.close(fd)
            self._sqlite_path = lock_path
            self._held = True
            logger.info("Instance lock acquired (sqlite lockfile %s)", lock_path)
            return True
        except FileExistsError:
            stale = self._try_steal_sqlite(lock_path)
            if stale:
                return self._acquire_sqlite(url)
            logger.warning(
                "Instance lock held by another process (%s); scheduler disabled",
                lock_path,
            )
            return False
        except Exception:  # noqa: BLE001
            logger.exception("Sqlite lockfile failed; scheduler disabled")
            return False

    def _try_steal_sqlite(self, lock_path: Path) -> bool:
        try:
            pid = int(lock_path.read_text().strip() or "0")
        except (OSError, ValueError):
            pid = 0
        if pid and not _pid_is_alive(pid):
            logger.warning("Instance lock owner pid=%s is dead; stealing lock", pid)
            lock_path.unlink(missing_ok=True)
            return True
        return False

    # -- release ------------------------------------------------------------
    def release(self) -> None:
        if self._held:
            if self._pg_conn is not None:
                try:
                    self._pg_conn.execute(
                        __import__("sqlalchemy").text(
                            "SELECT pg_advisory_unlock(hashtext(:name))"
                        ),
                        {"name": self._name},
                    )
                except Exception:  # noqa: BLE001
                    logger.debug("Advisory unlock failed (session close releases it)")
                self._pg_conn.close()
                self._pg_conn = None
            if self._sqlite_path is not None:
                try:
                    self._sqlite_path.unlink(missing_ok=True)
                except OSError:
                    pass
            self._held = False
            logger.info("Instance lock released")


_lock: InstanceLock | None = None


def acquire_instance_lock(engine: Engine, name: str = LOCK_NAME) -> bool:
    global _lock
    if _lock is not None:
        return _lock._held or _lock.acquire()
    _lock = InstanceLock(engine, name)
    return _lock.acquire()


def release_instance_lock() -> None:
    if _lock is not None:
        _lock.release()


def instance_lock_status() -> dict:
    return {
        "enabled": True,
        "held": _lock._held if _lock else False,
        "holder_pid": os.getpid(),
    }