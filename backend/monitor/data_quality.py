"""Background monitoring for data quality (auto-fix corrupted data).

A daemon thread started with the API: every ``DATA_QUALITY_MONITOR_SECONDS``
it persists a quality snapshot for the history endpoint and - when the
sliding-window corruption rate crosses the CRITICAL threshold - triggers
the repair sequence automatically (clear logs, restart EventLog service,
retrain ML, notify the admin).
"""
from __future__ import annotations

import logging
import threading

from backend.config import (
    DATA_QUALITY_AUTO_REPAIR,
    DATA_QUALITY_CRITICAL_RATE,
    DATA_QUALITY_MONITOR_SECONDS,
)

logger = logging.getLogger("baraq.data_quality")

_monitor_thread: threading.Thread | None = None
_stop = threading.Event()


def _monitor_loop() -> None:
    while not _stop.wait(DATA_QUALITY_MONITOR_SECONDS):
        try:
            from backend.collectors.quality import persist_snapshot, quality
            from backend.collectors.repair import run_repair
            from backend.database.connection import SessionLocal

            with SessionLocal() as db:
                rate = quality.window_rate()
                if DATA_QUALITY_AUTO_REPAIR and rate >= DATA_QUALITY_CRITICAL_RATE:
                    logger.warning(
                        "Data-quality corruption rate %.1f%% crossed CRITICAL "
                        "(%.1f%%) - running auto-repair", rate * 100,
                        DATA_QUALITY_CRITICAL_RATE * 100,
                    )
                    run_repair(db, f"auto: corruption rate {rate * 100:.0f}%")
                persist_snapshot(db)
        except Exception:  # noqa: BLE001 - monitor must never kill the app
            logger.exception("Data-quality monitor cycle failed")


def start() -> threading.Thread:
    """Start (or return) the daemon monitor thread."""
    global _monitor_thread
    if _monitor_thread and _monitor_thread.is_alive():
        return _monitor_thread
    _stop.clear()
    _monitor_thread = threading.Thread(
        target=_monitor_loop, name="baraq-data-quality-monitor", daemon=True
    )
    _monitor_thread.start()
    return _monitor_thread


def stop(timeout: float = 5.0) -> None:
    _stop.set()
    if _monitor_thread:
        _monitor_thread.join(timeout=timeout)