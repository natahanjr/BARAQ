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
from backend.detection.contract import DETECTION
from backend.detection.engine import persist, run_detection
from backend.detection.evidence import Evidence
from backend.detection.models import DetectionRecord
from backend.detection.registry import default_registry
from backend.security import require_auth
from backend.telemetry.ingestion.pipeline import normalize as normalize_event

router = APIRouter(
    prefix="/api/detections",
    tags=["detections-v2"],
    dependencies=[Depends(require_auth)],
)

# Spec (2.10) shows the detector catalog at /api/detectors; the canonical
# routes below live at /api/detections/detectors. Both surfaces are served
# from the same handlers.
detectors_router = APIRouter(
    prefix="/api/detectors",
    tags=["detectors-v2"],
    dependencies=[Depends(require_auth)],
)


def _explain_block(row: DetectionRecord) -> str:
    """Render the analyst-readable explainability block (contract 2.11)."""
    return DETECTION(
        detector_id=row.detector_id,
        detector_version=row.detector_version,
        detection_id=row.detection_id,
        event_id=row.event_id,
        event_ids=tuple(row.event_ids or ()),
        timestamp=row.timestamp,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        event_type="",  # not stored on DetectionRecord (contract-only field)
        host_id=row.host_id,
        host_name=row.host_name,
        user_id=row.user_id,
        username=row.username,
        source_ip=row.source_ip,
        destination_ip=row.destination_ip,
        title=row.title,
        description=row.description,
        severity=row.severity,
        confidence=row.confidence,
        mitre_tactic=row.mitre_tactic,
        mitre_technique=row.mitre_technique,
        evidence=tuple(Evidence(e["field"], e["value"], e["reason"]) for e in (row.evidence or [])),
        observables=tuple(dict(o) for o in (row.observables or [])),
        status=row.status,
    ).to_explain()


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
@detectors_router.get("")
def list_detectors():
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detectors": []}
    return {
        "status": "ok",
        "detectors": [d.describe() for d in default_registry().all()],
    }


@router.get("/detectors/{detector_id}")
@detectors_router.get("/{detector_id}")
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
            row = persist(db, detection)
            findings.append({**detection.to_dict(), "explain": _explain_block(row)})
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
    return {
        "status": "ok",
        "detection": row.to_dict(),
        "explain": _explain_block(row),
    }