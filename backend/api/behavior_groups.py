"""Phase 4 behavior group API (spec 4.31-4.33).

Read-oriented surface: list (with filters), detail, member alerts,
evidence, timeline, audit, metrics and an explicit close operation.
No arbitrary manual regrouping is exposed (spec 4.31). Gated by
``BEHAVIOR_GROUPS_ENABLED`` (PEP 562, mirroring telemetry/alerting) and
inert against the production database.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import config
from backend.aggregation import audit
from backend.aggregation import metrics as metrics_module
from backend.aggregation.contract import GROUP_STATUSES
from backend.aggregation.evaluation import run_evaluation
from backend.aggregation.lifecycle import IllegalTransition, apply_transition
from backend.aggregation.models import (
    BehaviorGroupAuditEvent,
    BehaviorGroupEvidence,
    BehaviorGroupRecord,
)
from backend.alerting.models import AlertRecord
from backend.database.connection import get_db
from backend.security import actor_name, require_auth


def __getattr__(name: str):
    """Expose the behavior-group gate dynamically (PEP 562)."""
    if name == "BEHAVIOR_GROUPS_ENABLED":
        return config.BEHAVIOR_GROUPS_ENABLED
    raise AttributeError(name)


router = APIRouter(
    prefix="/api/behavior-groups",
    tags=["behavior-groups"],
    dependencies=[Depends(require_auth)],
)


def _disabled() -> dict:
    return {"status": "disabled", "detail": "BEHAVIOR_GROUPS_ENABLED=0 in production"}


def _gate() -> None:
    if not config.BEHAVIOR_GROUPS_ENABLED:
        raise HTTPException(status_code=404, detail="behavior groups are disabled")


def _fetch(db: Session, group_id: str) -> BehaviorGroupRecord:
    row = db.scalars(
        select(BehaviorGroupRecord).where(
            BehaviorGroupRecord.behavior_group_id == group_id
        )
    ).first()
    if row is None:
        raise HTTPException(
            status_code=404, detail=f"unknown behavior group {group_id}"
        )
    return row


def _validate_status(status: str) -> None:
    if status not in GROUP_STATUSES:
        raise HTTPException(status_code=422, detail=f"invalid status {status!r}")


def _validate_severity(severity: str) -> None:
    if severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(status_code=422, detail=f"invalid severity {severity!r}")


@router.get("")
def list_groups(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    mitre_tactic: str | None = Query(default=None),
    mitre_technique: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    alert_count_min: int | None = Query(default=None, ge=0),
    first_seen_after: datetime | None = Query(default=None),
    last_seen_before: datetime | None = Query(default=None),
) -> dict:
    _gate()
    stmt = select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id)
    if status is not None:
        _validate_status(status)
        stmt = stmt.where(BehaviorGroupRecord.status == status)
    if host is not None:
        stmt = stmt.where(BehaviorGroupRecord.host_ids.contains([host]))
    if user is not None:
        stmt = stmt.where(BehaviorGroupRecord.user_ids.contains([user]))
    if source_ip is not None:
        stmt = stmt.where(BehaviorGroupRecord.source_ips.contains([source_ip]))
    if mitre_tactic is not None:
        stmt = stmt.where(BehaviorGroupRecord.mitre_tactics.contains([mitre_tactic]))
    if mitre_technique is not None:
        stmt = stmt.where(
            BehaviorGroupRecord.mitre_techniques.contains([mitre_technique])
        )
    if severity is not None:
        _validate_severity(severity)
        stmt = stmt.where(BehaviorGroupRecord.highest_severity == severity)
    if alert_count_min is not None:
        stmt = stmt.where(BehaviorGroupRecord.alert_count >= alert_count_min)
    if first_seen_after is not None:
        stmt = stmt.where(BehaviorGroupRecord.first_seen >= first_seen_after)
    if last_seen_before is not None:
        stmt = stmt.where(BehaviorGroupRecord.last_seen <= last_seen_before)
    rows = list(db.scalars(stmt).all())
    return {"total": len(rows), "behavior_groups": [r.to_dict() for r in rows]}


@router.get("/metrics")
def group_metrics(db: Session = Depends(get_db)) -> dict:
    _gate()
    return metrics_module.metrics(db)


@router.get("/evaluation")
def group_evaluation(db: Session = Depends(get_db)) -> dict:
    """Raw labeled grouping-quality counts (spec 4.41) - no fake accuracy."""
    _gate()
    return run_evaluation(db)


@router.get("/{group_id}")
def group_detail(group_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    group = _fetch(db, group_id)
    events = db.scalars(
        select(BehaviorGroupAuditEvent)
        .where(BehaviorGroupAuditEvent.behavior_group_id == group_id)
        .order_by(BehaviorGroupAuditEvent.id)
    ).all()
    return {
        "behavior_group": group.to_dict(),
        "audit": [
            (
                e.to_dict()
                if hasattr(e, "to_dict")
                else {
                    "action": e.action,
                    "actor": e.actor,
                    "details": e.details or {},
                    "created_at": e.created_at.isoformat(),
                }
            )
            for e in events
        ],
    }


@router.get("/{group_id}/alerts")
def group_alerts(group_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    group = _fetch(db, group_id)
    ids = list(group.alert_ids or [])
    rows = []
    if ids:
        rows = list(
            db.scalars(
                select(AlertRecord)
                .where(AlertRecord.alert_id.in_(ids))
                .order_by(AlertRecord.first_seen)
            ).all()
        )
    return {
        "behavior_group_id": group_id,
        "total": len(rows),
        "alerts": [r.to_dict() for r in rows],
    }


@router.get("/{group_id}/evidence")
def group_evidence(group_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    _fetch(db, group_id)
    rows = db.scalars(
        select(BehaviorGroupEvidence)
        .where(BehaviorGroupEvidence.behavior_group_id == group_id)
        .order_by(BehaviorGroupEvidence.id)
    ).all()
    return {
        "behavior_group_id": group_id,
        "total": len(rows),
        "evidence": [
            {
                "alert_id": r.alert_id,
                "field": r.field,
                "value": r.value,
                "reason": r.reason,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.get("/{group_id}/timeline")
def group_timeline(group_id: str, db: Session = Depends(get_db)) -> dict:
    """Chronological behavioral progression (spec 4.33)."""
    _gate()
    group = _fetch(db, group_id)
    ids = list(group.alert_ids or [])
    rows: list[dict] = []
    if ids:
        alerts = list(
            db.scalars(
                select(AlertRecord)
                .where(AlertRecord.alert_id.in_(ids))
                .order_by(AlertRecord.first_seen)
            ).all()
        )
        for alert in alerts:
            rows.append(
                {
                    "time": alert.first_seen.isoformat(),
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "detector_id": alert.detector_id,
                    "mitre_technique": alert.mitre_technique,
                }
            )
    return {"behavior_group_id": group_id, "timeline": rows}


@router.get("/{group_id}/audit")
def group_audit(group_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    _fetch(db, group_id)
    rows = db.scalars(
        select(BehaviorGroupAuditEvent)
        .where(BehaviorGroupAuditEvent.behavior_group_id == group_id)
        .order_by(BehaviorGroupAuditEvent.id)
    ).all()
    return {
        "behavior_group_id": group_id,
        "total": len(rows),
        "events": [
            {
                "action": r.action,
                "actor": r.actor,
                "details": r.details or {},
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.post("/{group_id}/close")
def close_group(group_id: str, request: Request, db: Session = Depends(get_db)) -> dict:
    _gate()
    group = _fetch(db, group_id)
    try:
        action = apply_transition(group, "CLOSED", datetime.now(UTC))
    except IllegalTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    audit.record(
        db,
        group_id=group_id,
        action=action,
        actor=actor_name(request),
        details={"source": "analyst"},
    )
    db.commit()
    return {"behavior_group_id": group_id, "status": "CLOSED", "action": action}
