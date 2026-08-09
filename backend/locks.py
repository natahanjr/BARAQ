"""Single-instance guard: only one SentinelSOC process may run the scheduler.

Two uvicorn processes pointed at the same database would both collect,
detect, retrain and retain - duplicating alerts and racing the graph
build. ``acquire_instance_lock`` grabs a database-scoped PostgreSQL
advisory lock at startup; a second process fails to acquire it and skips
the scheduler instead of corrupting state.

The lock is held for the process lifetime and released on shutdown, or
auto-released by the database if the connection drops.
"""
from __future__ import annotations

import logging
import os

from sqlalchemy.engine import Engine

logger = logging.getLogger("sentinel.locks")

LOCK_NAME = "sentinel-soc-scheduler"


class InstanceLock:
    """Database-scoped advisory lock held for the life of the process."""

    def __init__(self, engine: Engine, name: str = LOCK_NAME):
        self._engine = engine
        self._name = name
        self._pg_conn = None
        self._held = False

    # -- acquisition --------------------------------------------------------
    def acquire(self) -> bool:
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