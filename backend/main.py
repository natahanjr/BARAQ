"""SentinelSOC FastAPI application."""
from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import (
    alerts,
    assistant,
    dashboard,
    evaluation,
    events,
    investigation,
    reports,
    system,
)
from backend.config import CORS_ORIGINS
from backend.database.connection import SessionLocal, init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
logger = logging.getLogger("sentinel")

_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()


def _scheduler_loop(interval_seconds: int = 15):
    """Background collection + detection loop."""
    logger.info("Scheduler started (interval=%ss)", interval_seconds)
    from backend.analyzers import dashboard
    from backend.collectors import CollectorManager
    from backend.database.connection import SessionLocal
    from backend.ml.anomaly import get_detector

    manager = CollectorManager()
    from backend.api.system import run_pipeline

    counter = 0
    while not _scheduler_stop.is_set():
        try:
            db = SessionLocal()
            try:
                records = manager.collect()
                if records:
                    result = run_pipeline(db, records)
                    logger.info(
                        "Scheduler cycle: %d records, %d new alerts",
                        result["collected"], result["alerts_created"],
                    )
                counter += 1
                if counter % 20 == 0:
                    dashboard.snapshot(db)
                if counter % 10 == 0 and get_detector().is_ready:
                    get_detector().analyze_events(db, hours=1)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scheduler cycle failed: %s", exc)
        _scheduler_stop.wait(interval_seconds)
    logger.info("Scheduler stopped")


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    init_db()
    global _scheduler_thread
    if not _scheduler_thread or not _scheduler_thread.is_alive():
        _scheduler_stop.clear()
        from backend.config import COLLECT_INTERVAL_SECONDS
        _scheduler_thread = threading.Thread(
            target=_scheduler_loop, args=(COLLECT_INTERVAL_SECONDS,), daemon=True
        )
        _scheduler_thread.start()
    logger.info("SentinelSOC API is ready")
    yield
    _scheduler_stop.set()
    if _scheduler_thread:
        _scheduler_thread.join(timeout=5)
    logger.info("SentinelSOC API shut down")


app = FastAPI(
    title="SentinelSOC API",
    description=(
        "Intelligent Lightweight Security Operations Center Platform for "
        "Real-Time Windows Threat Detection and Incident Analysis"
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for router in (
    dashboard.router,
    alerts.router,
    events.router,
    investigation.router,
    reports.router,
    assistant.router,
    evaluation.router,
    system.router,
):
    app.include_router(router)


@app.get("/")
def root():
    return {
        "application": "SentinelSOC",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/api/system/status",
    }


@app.get("/api/health")
def health():
    return {"status": "ok"}
