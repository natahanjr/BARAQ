"""v2 telemetry API (Phase 1).

POST /api/v2/telemetry/ingest  - push raw records into the v2 pipeline
GET  /api/v2/telemetry/events   - recent v2 EVENTS (dev/verification only)

Read/write happens against the v2 telemetry table only. In production the
ingest endpoint is read-only-fails (the v2 pipeline is not live yet) - see
config ``TELEMETRY_V2_ENABLED``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import config
from backend.database.connection import get_db
from backend.security import require_auth
from backend.telemetry.ingestion.pipeline import ingest
from backend.telemetry.models import TelemetryEvent


def __getattr__(name: str):
    """Expose the v2 enable flag dynamically (PEP 562).

    ``backend.api.telemetry.TELEMETRY_V2_ENABLED`` always reflects the
    current value in ``backend.config`` (which includes the production-DB
    isolation gate), so a runtime change - e.g. tests monkeypatching the
    gate - is visible to callers. A plain ``from ... import`` at module
    load would freeze a stale copy and defeat the gate.
    """
    if name == "TELEMETRY_V2_ENABLED":
        return config.TELEMETRY_V2_ENABLED
    raise AttributeError(name)


router = APIRouter(
    prefix="/api/v2/telemetry",
    tags=["telemetry-v2"],
    dependencies=[Depends(require_auth)],
)


@router.post("/ingest")
def ingest_events(
    payload: dict,
    db: Session = Depends(get_db),
):
    """Accept a batch of raw records: ``{"records": [...]}``."""
    if not config.TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detail": "TELEMETRY_V2_ENABLED=0 in production"}
    records = payload.get("records") or []
    if not isinstance(records, list):
        return {"status": "error", "detail": "payload.records must be a list"}
    stats = ingest(db, records)
    return {"status": "ok", **stats}


@router.get("/events")
def list_events(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    """Recent v2 EVENTS (newest first) - for verification only."""
    if not config.TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "events": []}
    rows = db.scalars(
        select(TelemetryEvent).order_by(TelemetryEvent.id.desc()).limit(limit)
    ).all()
    return {
        "status": "ok",
        "events": [
            {
                "fingerprint": r.fingerprint,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "host": r.host,
                "user": r.user,
                "source": r.source,
                "action": r.action,
                "facts": r.facts,
                "event_id": r.event_id,
                "event_type": r.event_type,
                "destination": r.destination,
                "process": r.process,
                "network": r.network,
                "outcome": r.outcome,
            }
            for r in rows
        ],
    }
