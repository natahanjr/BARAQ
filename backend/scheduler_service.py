"""Standalone scheduler service (roadmap 3.1: "scheduler as a service").

Run the collection + detection loop as its own process so API replicas
stay stateless and the scheduler can be scaled/monitored independently:

    python -m backend.scheduler_service

The scheduler acquires the distributed instance lock (Redis when
BARAQ_REDIS_URL is set, otherwise the PostgreSQL advisory lock), so only
one scheduler runs per deployment even with many API replicas. API
processes should be started with BARAQ_ROLE=api to keep them scheduler-free
and fully horizontal.
"""
from __future__ import annotations

import logging
import os
import signal
import threading

from backend.logging_config import setup_logging

logger = logging.getLogger("baraq.scheduler_service")


def run(interval_seconds: int | None = None) -> None:
    from backend.config import APP_ROLE, COLLECT_INTERVAL_SECONDS
    from backend.database.connection import engine, init_db
    from backend.locks import acquire_instance_lock, release_instance_lock

    if APP_ROLE == "api":
        logger.error(
            "BARAQ_ROLE=api refuses to run the scheduler service; "
            "set BARAQ_ROLE=all or scheduler"
        )
        raise SystemExit(2)

    init_db()
    if not acquire_instance_lock(engine):
        logger.critical(
            "Another process holds the scheduler lock; exiting (zero-downtime: "
            "the remaining scheduler keeps collecting)."
        )
        raise SystemExit(1)

    from backend.main import _scheduler_loop, _scheduler_stop

    stop = threading.Event()
    stop_flag = {"set": False}

    def _shutdown(_sig, _frame):  # noqa: ARG001
        logger.info("Signal received; stopping scheduler")
        _scheduler_stop.set()
        stop_flag["set"] = True

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    interval = interval_seconds or COLLECT_INTERVAL_SECONDS
    thread = threading.Thread(
        target=_scheduler_loop, args=(interval,), daemon=True,
        name="baraq-scheduler",
    )
    thread.start()
    logger.info(
        "Standalone scheduler running (interval=%ss); press Ctrl+C to stop",
        interval,
    )
    try:
        while not stop_flag["set"]:
            stop.wait(1)
    finally:
        _scheduler_stop.set()
        thread.join(timeout=10)
        release_instance_lock()
        logger.info("Standalone scheduler stopped")


if __name__ == "__main__":
    setup_logging()
    run()