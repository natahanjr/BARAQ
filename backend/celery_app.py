"""Optional Celery integration (roadmap 3.1: job queue / read replicas).

BARAQ runs fine without Celery - the built-in scheduler thread covers
collection and detection, and API requests run synchronously. When you
deploy multi-node (K8s, separate workers) you can opt into Celery for the
long-running jobs (ML training, reports, intel ingestion, retention):

    pip install celery redis
    celery -A backend.celery_app worker -Q baraq -l info

Nothing imports this module unless ``BARAQ_CELERY=1``; the app object is
only created on demand so the rest of the platform stays dependency-free.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("baraq.celery")


def _make_celery_app():
    from celery import Celery  # type: ignore[import-not-found]

    from backend.config import REDIS_URL

    broker = os.environ.get(
        "BARAQ_CELERY_BROKER", REDIS_URL or "redis://localhost:6379/0"
    )
    app = Celery("baraq", broker=broker, backend=broker)
    app.conf.update(
        task_default_queue="baraq",
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        task_time_limit=3600,
        broker_connection_retry_on_startup=True,
    )
    return app


def get_celery():
    """Celery application instance (lazy, only when BARAQ_CELERY=1)."""
    if os.environ.get("BARAQ_CELERY", "0").lower() not in ("1", "true", "yes", "on"):
        return None
    return _make_celery_app()


def enqueue_if_enabled(name: str, *args, **kwargs) -> bool:
    """Dispatch a job to Celery when enabled; returns False otherwise."""
    app = get_celery()
    if app is None:
        return False
    try:
        app.send_task(name, args=args, kwargs=kwargs, queue="baraq")
        return True
    except Exception as exc:
        logger.warning("Celery dispatch of %s failed: %s", name, exc)
        return False


# ---------------------------------------------------------------------------
# Task wrappers (run with: celery -A backend.celery_app worker)
# ---------------------------------------------------------------------------
def register_tasks() -> None:
    app = get_celery()
    if app is None:
        return

    @app.task(name="baraq.ml_train")
    def ml_train(hours: int = 24, force: bool = False) -> dict:
        from backend.database.connection import SessionLocal
        from backend.ml.anomaly import get_detector

        with SessionLocal() as db:
            return get_detector().train(db, hours=hours, validate=not force)

    @app.task(name="baraq.retention")
    def retention() -> dict:
        from backend.database.connection import SessionLocal
        from backend.database.retention import purge_old_data

        with SessionLocal() as db:
            return purge_old_data(db)

    @app.task(name="baraq.scheduled_report")
    def scheduled_report(report_type: str = "daily", fmt: str = "pdf") -> dict:
        from backend.database.connection import SessionLocal
        from backend.reports import generate_report

        if report_type not in ("executive", "technical"):
            report_type = "executive"
        with SessionLocal() as db:
            return generate_report(db, report_type=report_type, fmt=fmt)

    @app.task(name="baraq.intel_refresh")
    def intel_refresh() -> dict:
        from backend.database.connection import SessionLocal
        from backend.intel.feeds import refresh_feeds

        with SessionLocal() as db:
            return refresh_feeds(db)


register_tasks()
