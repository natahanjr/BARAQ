"""v2 alert API (Phase 3).

Analyst-facing alert management surface. Namespaced at ``/api/alerts-v2``
because the v1 alerts API owns ``/api/alerts`` (integer ids, incident/risk
side effects); this is the documented deviation from the spec's example
paths (spec 3.20). Every state-changing endpoint validates legal lifecycle
transitions, records an audit event, and can never create incidents,
mutate risk or execute SOAR.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import config
from backend.alerting import audit
from backend.alerting import feedback as feedback_mod
from backend.alerting.lifecycle import IllegalTransition, transition
from backend.alerting.metrics import metrics as alert_metrics
from backend.alerting.models import (
    AlertOccurrence,
    AlertRecord,
    AlertSuppressionRule,
)
from backend.alerting.suppression import create_rule
from backend.database.connection import get_db
from backend.security import actor_name, require_auth


def __getattr__(name: str):
    """Expose the v2 alert gate dynamically (PEP 562), mirroring telemetry.py."""
    if name == "ALERTS_V2_ENABLED":
        return config.ALERTS_V2_ENABLED
    raise AttributeError(name)


router = APIRouter(
    prefix="/api/alerts-v2",
    tags=["alerts-v2"],
    dependencies=[Depends(require_auth)],
)

_ACTIVE_STATUSES = ("OPEN", "ACKNOWLEDGED", "IN_PROGRESS")


def _fetch(db: Session, alert_id: str) -> AlertRecord:
    row = db.scalars(
        select(AlertRecord).where(AlertRecord.alert_id == alert_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown alert {alert_id}")
    return row


def _validate_status(status: str) -> None:
    if status not in (
        "OPEN",
        "ACKNOWLEDGED",
        "IN_PROGRESS",
        "RESOLVED",
        "CLOSED",
        "SUPPRESSED",
    ):
        raise HTTPException(status_code=422, detail=f"invalid status {status!r}")


def _validate_severity(severity: str) -> None:
    if severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=422, detail=f"invalid severity {severity!r}")


def _apply_transition(
    db: Session, row: AlertRecord, target: str, action: str, actor: str
) -> dict:
    try:
        t = transition(row.status, target, reopen=(action == "REOPENED"))
    except IllegalTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    row.status = t.new_status
    row.updated_at = datetime.now(UTC)
    if t.new_status == "ACKNOWLEDGED":
        row.acknowledged_at = row.updated_at
        row.acknowledged_by = actor
    if t.new_status == "RESOLVED":
        row.resolved_at = row.updated_at
    audit.record(
        db,
        alert_id=row.alert_id,
        action=t.action,
        previous_status=t.previous_status,
        new_status=t.new_status,
        actor=actor,
    )
    db.commit()
    return {"status": "ok", "alert": row.to_dict()}


@router.get("")
def list_alerts(
    request: Request,
    severity: str | None = Query(None),
    status: str | None = Query(None),
    detector: str | None = Query(None),
    mitre: str | None = Query(None),
    host: str | None = Query(None),
    user: str | None = Query(None),
    source_ip: str | None = Query(None),
    assigned_to: str | None = Query(None),
    feedback: str | None = Query(None),
    first_seen_from: datetime | None = Query(None),
    first_seen_to: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Alert queue with filtering (spec 3.21, 3.22)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "items": []}
    if severity:
        _validate_severity(severity)
    if status:
        _validate_status(status)
    stmt = select(AlertRecord).order_by(AlertRecord.first_seen.desc())
    if severity:
        stmt = stmt.where(AlertRecord.severity == severity)
    if status:
        stmt = stmt.where(AlertRecord.status == status)
    if detector:
        stmt = stmt.where(AlertRecord.detector_id == detector)
    if mitre:
        stmt = stmt.where(AlertRecord.mitre_technique == mitre)
    if host:
        stmt = stmt.where(AlertRecord.host_name == host)
    if user:
        stmt = stmt.where(AlertRecord.username == user)
    if source_ip:
        stmt = stmt.where(AlertRecord.source_ip == source_ip)
    if assigned_to:
        stmt = stmt.where(AlertRecord.assigned_to == assigned_to)
    if feedback:
        stmt = stmt.where(AlertRecord.feedback == feedback)
    if first_seen_from:
        stmt = stmt.where(AlertRecord.first_seen >= first_seen_from)
    if first_seen_to:
        stmt = stmt.where(AlertRecord.first_seen <= first_seen_to)
    rows = db.scalars(stmt.offset(offset).limit(limit)).all()
    now = datetime.now(UTC)
    items = []
    for r in rows:
        item = r.to_dict()
        age_seconds = int((now - r.first_seen).total_seconds()) if r.first_seen else 0
        item["age_seconds"] = age_seconds
        item["age"] = _age_label(age_seconds)
        items.append(item)
    return {"status": "ok", "total": len(items), "items": items}


def _age_label(age_seconds: int) -> str:
    if age_seconds < 900:
        return "0-15m"
    if age_seconds < 3600:
        return "15-60m"
    if age_seconds < 14400:
        return "1-4h"
    return "4h+"


@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)):
    """Alert metrics (spec 3.36, 3.37)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "metrics": {}}
    return {"status": "ok", "metrics": alert_metrics(db)}


@router.get("/feedback-stats")
def get_feedback_stats(db: Session = Depends(get_db)):
    """Feedback + false-positive statistics (spec 3.14, 3.15)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "stats": {}}
    return {
        "status": "ok",
        "stats": feedback_mod.stats(db, config.ALERT_MIN_LABELED_FOR_FPR),
    }


@router.get("/suppressions")
def list_suppressions(db: Session = Depends(get_db)):
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "items": []}
    rows = db.scalars(
        select(AlertSuppressionRule).order_by(AlertSuppressionRule.created_at.desc())
    ).all()
    return {"status": "ok", "items": [_suppression_dict(r) for r in rows]}


@router.post("/suppressions")
def add_suppression(request: Request, payload: dict, db: Session = Depends(get_db)):
    """Create an auditable, expiring suppression rule (spec 3.25/3.26)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "rule": None}
    reason = str(payload.get("reason") or "").strip()
    if not reason:
        raise HTTPException(
            status_code=422, detail="suppression requires a documented reason"
        )
    expires = payload.get("expires_at")
    if not expires:
        raise HTTPException(
            status_code=422, detail="suppression requires an expiration"
        )
    try:
        expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="invalid expires_at") from exc
    try:
        rule = create_rule(
            db,
            policy_id=str(
                payload.get("policy_id") or f"SUP-{int(datetime.now(UTC).timestamp())}"
            ),
            reason=reason,
            expires_at=expires_at,
            scope=payload.get("scope") or {},
            created_by=actor_name(request),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    db.commit()
    return {"status": "ok", "rule": _suppression_dict(rule)}


def _suppression_dict(r: AlertSuppressionRule) -> dict:
    return {
        "policy_id": r.policy_id,
        "reason": r.reason,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "expires_at": r.expires_at.isoformat() if r.expires_at else None,
        "scope": r.scope or {},
        "suppressed_count": r.suppressed_count,
    }


@router.get("/{alert_id}")
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """Alert detail (spec 3.43)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    row = _fetch(db, alert_id)
    return {
        "status": "ok",
        "alert": row.to_dict(),
        "audit": [
            {
                "action": e.action,
                "previous_status": e.previous_status,
                "new_status": e.new_status,
                "actor": e.actor,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in audit.for_alert(db, alert_id)
        ],
    }


@router.get("/{alert_id}/occurrences")
def get_occurrences(alert_id: str, db: Session = Depends(get_db)):
    """All merged occurrences (spec 3.17, 3.33)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "items": []}
    _fetch(db, alert_id)
    rows = db.scalars(
        select(AlertOccurrence)
        .where(AlertOccurrence.alert_id == alert_id)
        .order_by(AlertOccurrence.timestamp, AlertOccurrence.id)
    ).all()
    return {
        "status": "ok",
        "items": [
            {
                "detection_id": r.detection_id,
                "event_ids": list(r.event_ids or []),
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "evidence": list(r.evidence or []),
            }
            for r in rows
        ],
    }


@router.get("/{alert_id}/evidence")
def get_evidence(alert_id: str, db: Session = Depends(get_db)):
    """Preserved detection evidence (spec 3.16)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "evidence": []}
    row = _fetch(db, alert_id)
    return {"status": "ok", "evidence": list(row.evidence or [])}


@router.post("/{alert_id}/acknowledge")
def acknowledge(alert_id: str, request: Request, db: Session = Depends(get_db)):
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "ACKNOWLEDGED", "ACKNOWLEDGED", actor_name(request)
    )


@router.post("/{alert_id}/in-progress")
def in_progress(alert_id: str, request: Request, db: Session = Depends(get_db)):
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "IN_PROGRESS", "IN_PROGRESS", actor_name(request)
    )


@router.post("/{alert_id}/assign")
def assign(
    alert_id: str, request: Request, payload: dict, db: Session = Depends(get_db)
):
    """Assign to an analyst (spec 3.12). Never trusts client state."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    row = _fetch(db, alert_id)
    assigned_to = str(payload.get("assigned_to") or "").strip()
    if not assigned_to:
        raise HTTPException(status_code=422, detail="assigned_to is required")
    row.assigned_to = assigned_to
    row.assigned_at = datetime.now(UTC)
    row.updated_at = row.assigned_at
    audit.record(
        db,
        alert_id=row.alert_id,
        action="ASSIGNED",
        previous_status=row.status,
        new_status=row.status,
        actor=actor_name(request),
        details={"assigned_to": assigned_to},
    )
    db.commit()
    return {"status": "ok", "alert": row.to_dict()}


@router.post("/{alert_id}/resolve")
def resolve(alert_id: str, request: Request, db: Session = Depends(get_db)):
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "RESOLVED", "RESOLVED", actor_name(request)
    )


@router.post("/{alert_id}/close")
def close(alert_id: str, request: Request, db: Session = Depends(get_db)):
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "CLOSED", "CLOSED", actor_name(request)
    )


@router.post("/{alert_id}/reopen")
def reopen(alert_id: str, request: Request, db: Session = Depends(get_db)):
    """Explicit reopen operation (spec 3.11): CLOSED/RESOLVED/SUPPRESSED -> OPEN."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "OPEN", "REOPENED", actor_name(request)
    )


@router.post("/{alert_id}/suppress")
def suppress(alert_id: str, request: Request, db: Session = Depends(get_db)):
    """Manually suppress an active alert (documented, audited)."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "alert": None}
    return _apply_transition(
        db, _fetch(db, alert_id), "SUPPRESSED", "SUPPRESSED", actor_name(request)
    )


@router.post("/{alert_id}/feedback")
def submit_feedback(
    alert_id: str, request: Request, payload: dict, db: Session = Depends(get_db)
):
    """Structured feedback (spec 3.14). Server-side validation of every value."""
    if not config.ALERTS_V2_ENABLED:
        return {"status": "disabled", "feedback": None}
    row = _fetch(db, alert_id)
    feedback_type = str(payload.get("feedback_type") or "").upper()
    if feedback_type not in (
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "BENIGN",
        "DUPLICATE",
        "EXPECTED_ACTIVITY",
        "UNKNOWN",
    ):
        raise HTTPException(
            status_code=422, detail=f"invalid feedback_type {feedback_type!r}"
        )
    comment = str(payload.get("comment") or "").strip()
    actor = actor_name(request)
    fb = feedback_mod.submit(db, row.alert_id, feedback_type, actor, comment)
    row.feedback = feedback_type
    row.updated_at = datetime.now(UTC)
    audit.record(
        db,
        alert_id=row.alert_id,
        action="FEEDBACK",
        previous_status=row.status,
        new_status=row.status,
        actor=actor,
        details={"feedback_type": feedback_type},
    )
    db.commit()
    return {
        "status": "ok",
        "feedback": {
            "alert_id": fb.alert_id,
            "feedback_type": fb.feedback_type,
            "analyst": fb.analyst_id,
            "comment": fb.comment,
            "created_at": fb.created_at.isoformat() if fb.created_at else None,
        },
    }
