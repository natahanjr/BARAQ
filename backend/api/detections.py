"""v2 detection API (Phase 2).

Read-only endpoints over the detection store plus a controlled
``evaluate`` endpoint that only processes supplied telemetry. Nothing here
creates alerts, incidents, risk updates or SOAR actions.

Like the v2 telemetry API, this surface is inert on the production
database (``TELEMETRY_V2_ENABLED`` gate + engine-level guard).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
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

import logging
logger = logging.getLogger("baraq.api.detections")

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
        evidence=tuple(
            Evidence(e["field"], e["value"], e["reason"]) for e in (row.evidence or [])
        ),
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
    detectors = []
    for d in default_registry().all():
        info = d.describe()
        info["id"] = info["detector_id"]
        info["mitre_technique"] = ""
        info["category"] = "detection"
        info["severity"] = "medium"
        detectors.append(info)
    try:
        from backend.detection.rules_engine import build_rules
        from backend.database.connection import SessionLocal
        with SessionLocal() as session:
            rules = build_rules(session)
        for r in rules:
            detectors.append({
                "id": r.rule_id,
                "detector_id": r.rule_id,
                "name": r.name,
                "description": r.description,
                "severity": r.severity,
                "mitre_technique": r.mitre_id,
                "mitre_id": r.mitre_id,
                "confidence": r.confidence,
                "enabled": True,
                "category": _categorize_mitre(r.mitre_id),
                "version": "1.0.0",
                "source": "v1",
            })
    except Exception as exc:
        logger.warning("Failed to enumerate v1 rules: %s", exc)
    return {
        "status": "ok",
        "detectors": detectors,
    }


MITRE_TACTIC_MAP = {
    "T1566": "initial-access", "T1190": "initial-access", "T1133": "initial-access",
    "T1078": "initial-access", "T1195": "initial-access",
    "T1059": "execution", "T1047": "execution", "T1053": "execution",
    "T1204": "execution", "T1106": "execution", "T1569": "execution",
    "T1055": "defense-evasion", "T1027": "defense-evasion", "T1140": "defense-evasion",
    "T1036": "defense-evasion", "T1574": "defense-evasion", "T1218": "defense-evasion",
    "T1562": "defense-evasion", "T1070": "defense-evasion", "T1202": "defense-evasion",
    "T1222": "defense-evasion", "T1112": "defense-evasion", "T1211": "defense-evasion",
    "T1553": "defense-evasion", "T1480": "defense-evasion", "T1056": "credential-access",
    "T1003": "credential-access", "T1110": "credential-access", "T1558": "credential-access",
    "T1557": "credential-access", "T1555": "credential-access", "T1539": "credential-access",
    "T1528": "credential-access", "T1552": "credential-access",
    "T1021": "lateral-movement", "T1570": "lateral-movement", "T1563": "lateral-movement",
    "T1080": "lateral-movement", "T1550": "lateral-movement",
    "T1018": "discovery", "T1082": "discovery", "T1083": "discovery",
    "T1087": "discovery", "T1135": "discovery", "T1046": "discovery",
    "T1069": "discovery", "T1518": "discovery", "T1049": "discovery",
    "T1486": "impact", "T1485": "impact", "T1490": "impact",
    "T1489": "impact", "T1498": "impact", "T1499": "impact",
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    "T1029": "exfiltration", "T1030": "exfiltration",
    "T1071": "command-and-control", "T1105": "command-and-control",
    "T1572": "command-and-control", "T1090": "command-and-control",
    "T1571": "command-and-control", "T1095": "command-and-control",
    "T1547": "persistence", "T1136": "persistence", "T1053": "persistence",
    "T1543": "persistence", "T1546": "persistence", "T1098": "persistence",
    "T1076": "persistence", "T1505": "persistence", "T1137": "persistence",
    "T1542": "persistence",
}


def _categorize_mitre(mitre_id: str) -> str:
    for prefix, tactic in sorted(MITRE_TACTIC_MAP.items(), key=lambda x: -len(x[0])):
        if mitre_id.startswith(prefix):
            return tactic
    return "general"


@router.get("/detectors/{detector_id}")
@detectors_router.get("/{detector_id}")
def get_detector(detector_id: str):
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detector": None}
    detector = default_registry().get(detector_id)
    if detector is None:
        return {"status": "error", "detail": f"unknown detector {detector_id}"}
    return {"status": "ok", "detector": detector.describe()}


class EvaluateRequest(BaseModel):
    records: list = Field(default_factory=list)


@router.post("/evaluate")
def evaluate_telemetry(
    payload: EvaluateRequest,
    db: Session = Depends(get_db),
):
    """Evaluate supplied telemetry records only. Persists DETECTIONs; never
    creates alerts/incidents/risk/SOAR. Inert on the production DB."""
    if not TELEMETRY_V2_ENABLED:
        return {"status": "disabled", "detections": []}
    records = payload.records or []
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
