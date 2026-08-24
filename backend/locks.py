"""Scheduler locking: single-writer guarantee across BARAQ processes.

Two uvicorn processes pointed at the same database would both collect,
detect, retrain and retain - duplicating alerts and racing the graph
build. One lock is held by the process that runs the scheduler; everyone
else serves API reads only.

Two backends are supported (roadmap 3.1 multi-node):

* **PostgreSQL advisory lock** - default; single-writer per database.
  Requires no extra infrastructure.
* **Redis SET NX EX** - when ``BARAQ_REDIS_URL`` is set; lets several API
  replicas race fairly for one scheduler while their database stays
  unburdened. The TTL is re-armed (heartbeat) during long scheduler cycles.

The lock is held for the process lifetime and released on shutdown, or
auto-released by the backend if the process dies.
"""
from __future__ import annotations

import logging
import os
import threading
import time
import uuid

from sqlalchemy.engine import Engine

logger = logging.getLogger("baraq.locks")

LOCK_NAME = "baraq-soc-scheduler"


class InstanceLock:
    """Distributed lock held for the life of the scheduler process."""

    def __init__(self, engine: Engine | None = None, name: str = LOCK_NAME):
        self._engine = engine
        self._name = name
        self._pg_conn = None
        self._redis = None
        self._redis_token = None
        self._held = False
        self._heartbeat_stop = None
        self._heartbeat_thread = None

    # -- acquisition --------------------------------------------------------
    def acquire(self) -> bool:
        if self._acquire_redis():
            return True
        return self._acquire_postgres()

    def _acquire_redis(self) -> bool:
        from backend.config import REDIS_URL

        if not REDIS_URL:
            return False
        try:
            import redis  # type: ignore[import-not-found]
        except ImportError:
            logger.warning(
                "BARAQ_REDIS_URL is set but the 'redis' package is not "
                "installed; falling back to the PostgreSQL lock"
            )
            return False
        try:
            client = redis.Redis.from_url(REDIS_URL, socket_timeout=5, decode_responses=True)
            token = uuid.uuid4().hex
            got = client.set(self._name, token, nx=True, ex=30)
            if not got:
                logger.warning(
                    "Redis scheduler lock held by another process; "
                    "scheduler disabled on this instance"
                )
                return False
            self._redis = client
            self._redis_token = token
            self._held = True
            self._start_heartbeat()
            logger.info("Instance lock acquired (redis, %s)", self._name)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Redis lock unavailable (%s); falling back to Postgres", exc)
            return False

    def _start_heartbeat(self) -> None:
        from backend.config import SCHEDULER_LOCK_TTL_SECONDS

        def _beat():
            while not self._heartbeat_stop.is_set():
                try:
                    self._redis.set(self._name, self._redis_token, ex=SCHEDULER_LOCK_TTL_SECONDS)
                except Exception:  # noqa: BLE001
                    logger.debug("Redis lock heartbeat failed")
                self._heartbeat_stop.wait(SCHEDULER_LOCK_TTL_SECONDS / 3)

        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = threading.Thread(target=_beat, daemon=True)
        self._heartbeat_thread.start()

    def _acquire_postgres(self) -> bool:
        if self._engine is None:
            return False
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
        if self._redis is not None:
            try:
                self._redis.eval(
                    "if redis.call('get', KEYS[1]) == ARGV[1] then "
                    "return redis.call('del', KEYS[1]) else return 0 end",
                    1, self._name, self._redis_token,
                )
            except Exception:  # noqa: BLE001
                logger.debug("Redis unlock failed (TTL will expire it)")
            self._redis.close()
            self._redis = None
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
        if self._heartbeat_stop is not None:
            self._heartbeat_stop.set()
            self._heartbeat_stop = None
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