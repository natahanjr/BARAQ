"""Scheduler hooks - called from the main BARAQ scheduler loop."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from .collector import active_collection, sweep

log = logging.getLogger("dataset.scheduler")


def dataset_sweep(session: Session, limit: int | None = None) -> dict:
    """Collect the next batch of telemetry into the research dataset.

    Cheap and safe to call every scheduler cycle; batching keeps the
    research store from ever competing with normal telemetry work.
    """
    try:
        return sweep(session, limit=limit)
    except Exception:  # noqa: BLE001
        log.warning("dataset sweep failed", exc_info=True)
        session.rollback()
        return {"collected": 0, "error": "sweep failed"}


def dataset_maybe_export(session: Session) -> dict:
    """Run the 24h automatic export when it is due (idempotent)."""
    try:
        coll = active_collection(session, create_if_missing=False)
        if coll is None or coll.status == "complete":
            return {"due": False}
        last = coll.last_export_at or coll.started_at
        if last is None:
            return {"due": False}
        due = datetime.now(timezone.utc) >= last + timedelta(hours=coll.export_interval_hours)
        if not due:
            return {"due": False}
        from .exporter import export_pending

        result = export_pending(session, coll.id, trigger="scheduled")
        return {"due": True, "result": result}
    except Exception:  # noqa: BLE001
        log.warning("dataset auto-export failed", exc_info=True)
        session.rollback()
        return {"due": False, "error": "auto-export failed"}