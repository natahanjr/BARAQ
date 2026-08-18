"""v2 detection API (Phase 2).

Read-only endpoints over the detection store plus a controlled
``evaluate`` endpoint that only processes supplied telemetry. Nothing here
creates alerts, incidents, risk updates or SOAR actions.

Like the v2 telemetry API, this surface is inert on the production
database (``TELEMETRY_V2_ENABLED`` gate + engine-level guard).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import TELEMETRY_V2_ENABLED
from backend.database.connection import get_db
from backend.detection.context import DetectionContext
from backend.detection.engine import persist, run_detection
from backend.detection.models import DetectionRecord
from backend.detection.registry import default_registry
from backend.security import require_auth
from backend.telemetry.ingestion.pipeline import normalize as normalize_event

router = APIRouter(
    prefix="/api/detections",
    tags=["detections-v2"],
    dependencies=[Depends(require_auth)],
)


@router.get("")
def list_detections(
    detector_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None, pattern="^(new|expired|suppressed)$"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detections": []}
    stmt = select(DetectionRecord).order_by(DetectionRecord.created_at.desc())
    if detector_id:
        stmt = stmt.where(DetectionRecord.detector_id == detector_id)
    if severity:
        stmt = stmt.where(DetectionRecord.severity == severity)
    if status:
        stmt = stmt.where(DetectionRecord.status == status)
    total = len(db.scalars(stmt).all())
    rows = db.scalars(stmt.offset(offset).limit(limit)).all()
    return {
        "status": "ok",
        "total": total,
        "items": [r.to_dict() for r in rows],
    }


@router.get("/detectors")
def list_detectors():
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detectors": []}
    return {
        "status": "ok",
        "detectors": [d.describe() for d in default_registry().all()],
    }


@router.get("/detectors/{detector_id}")
def get_detector(detector_id: str):
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detector": None}
    detector = default_registry().get(detector_id)
    if detector is None:
        return {"status": "error", "detail": f"unknown detector {detector_id}"}
    return {"status": "ok", "detector": detector.describe()}


@router.post("/evaluate")
def evaluate_telemetry(
    payload: dict,
    db: Session = Depends(get_db),
):
    """Evaluate supplied telemetry records only. Persists DETECTIONs; never
    creates alerts/incidents/risk/SOAR. Inert on the production DB."""
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detections": []}
    records = payload.get("records") or []
    if not isinstance(records, list):
        return {"status": "error", "detail": "payload.records must be a list"}

    context = DetectionContext(db)
    findings = []
    for raw in records:
        event = normalize_event(raw)
        if event is None:
            continue
        for detection in run_detection(event, context):
            persist(db, detection)
            findings.append(detection.to_dict())
    return {"status": "ok", "detections": findings}


@router.get("/{detection_id}")
def get_detection(detection_id: str, db: Session = Depends(get_db)):
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detection": None}
    row = db.scalars(
        select(DetectionRecord).where(DetectionRecord.detection_id == detection_id)
    ).first()
    if row is None:
        return {"status": "error", "detail": f"unknown detection {detection_id}"}
    return {"status": "ok", "detection": row.to_dict()}