"""Phase 5 correlation API (spec 5.52-5.58).

Read-oriented surface: list (with filters), detail, member groups, member
alerts, evidence, timeline, graph, audit, metrics and the rule registry.
No manual finding manipulation is exposed (spec 5.51). Gated by
``CORRELATION_ENABLED`` (PEP 562, mirroring telemetry/alerting/
aggregation) and inert against the production database.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend import config
from backend.alerting.models import AlertRecord
from backend.correlation import metrics as metrics_module
from backend.correlation.contract import CORRELATION_STATUSES, CORRELATION_TYPES
from backend.correlation.evaluation import run_evaluation
from backend.correlation.models import (
    CorrelationAuditEvent,
    CorrelationEdge,
    CorrelationEvidence,
    CorrelationFindingRecord,
    CorrelationMember,
)
from backend.correlation.registry import list_rules
from backend.database.connection import get_db
from backend.security import require_auth


def __getattr__(name: str):
    """Expose the correlation gate dynamically (PEP 562)."""
    if name == "CORRELATION_ENABLED":
        return config.CORRELATION_ENABLED
    raise AttributeError(name)


router = APIRouter(
    prefix="/api/correlations",
    tags=["correlations"],
    dependencies=[Depends(require_auth)],
)


def _gate() -> None:
    if not config.CORRELATION_ENABLED:
        raise HTTPException(status_code=404, detail="correlations are disabled")


def _fetch(db: Session, correlation_id: str) -> CorrelationFindingRecord:
    row = db.scalars(
        select(CorrelationFindingRecord).where(
            CorrelationFindingRecord.correlation_id == correlation_id
        )
    ).first()
    if row is None:
        raise HTTPException(
            status_code=404, detail=f"unknown correlation {correlation_id}"
        )
    return row


def _validate_status(status: str) -> None:
    if status not in CORRELATION_STATUSES:
        raise HTTPException(status_code=422, detail=f"invalid status {status!r}")


def _validate_type(correlation_type: str) -> None:
    if correlation_type not in CORRELATION_TYPES:
        raise HTTPException(
            status_code=422, detail=f"invalid correlation_type {correlation_type!r}"
        )


@router.get("")
def list_correlations(
    db: Session = Depends(get_db),
    status: str | None = Query(default=None),
    correlation_type: str | None = Query(default=None),
    host: str | None = Query(default=None),
    user: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    destination_ip: str | None = Query(default=None),
    tactic: str | None = Query(default=None),
    technique: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    confidence_min: float | None = Query(default=None, ge=0.0, le=1.0),
    first_seen_after: datetime | None = Query(default=None),
    last_seen_before: datetime | None = Query(default=None),
    member_count_min: int | None = Query(default=None, ge=2),
) -> dict:
    _gate()
    stmt = select(CorrelationFindingRecord).order_by(CorrelationFindingRecord.id)
    if status is not None:
        _validate_status(status)
        stmt = stmt.where(CorrelationFindingRecord.status == status)
    if correlation_type is not None:
        _validate_type(correlation_type)
        stmt = stmt.where(CorrelationFindingRecord.correlation_type == correlation_type)
    if host is not None:
        stmt = stmt.where(CorrelationFindingRecord.hosts.contains([host]))
    if user is not None:
        stmt = stmt.where(CorrelationFindingRecord.users.contains([user]))
    if source_ip is not None:
        stmt = stmt.where(CorrelationFindingRecord.source_ips.contains([source_ip]))
    if destination_ip is not None:
        stmt = stmt.where(
            CorrelationFindingRecord.observables["destination_ips"].contains(
                [destination_ip]
            )
        )
    if tactic is not None:
        stmt = stmt.where(CorrelationFindingRecord.mitre_tactics.contains([tactic]))
    if technique is not None:
        stmt = stmt.where(
            CorrelationFindingRecord.mitre_techniques.contains([technique])
        )
    if confidence_min is not None:
        stmt = stmt.where(CorrelationFindingRecord.confidence >= confidence_min)
    if first_seen_after is not None:
        stmt = stmt.where(CorrelationFindingRecord.first_seen >= first_seen_after)
    if last_seen_before is not None:
        stmt = stmt.where(CorrelationFindingRecord.last_seen <= last_seen_before)
    rows = list(db.scalars(stmt).all())
    if rule_id is not None:
        rows = [r for r in rows if _rule_fired(db, r.correlation_id, rule_id)]
    if member_count_min is not None:
        rows = [r for r in rows if len(r.member_group_ids or []) >= member_count_min]
    return {"total": len(rows), "correlations": [r.to_dict() for r in rows]}


def _rule_fired(db: Session, correlation_id: str, rule_id: str) -> bool:
    """True when any audit event on the finding mentions the rule."""
    for event in db.scalars(
        select(CorrelationAuditEvent).where(
            CorrelationAuditEvent.correlation_id == correlation_id
        )
    ).all():
        if (event.details or {}).get("rule_id") == rule_id:
            return True
    return False


@router.get("/metrics")
def correlation_metrics(db: Session = Depends(get_db)) -> dict:
    _gate()
    return metrics_module.metrics(db)


@router.get("/evaluation")
def correlation_evaluation(db: Session = Depends(get_db)) -> dict:
    """Raw labeled correlation-quality counts (spec 5.62) - no fake accuracy."""
    _gate()
    return run_evaluation(db)


@router.get("/rules")
def correlation_rules() -> dict:
    """Deterministic rule registry (spec 5.11): pure data, no ML."""
    _gate()
    return {"version": "1.0.0", "rules": list_rules()}


@router.get("/{correlation_id}")
def correlation_detail(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    finding = _fetch(db, correlation_id)
    edges = db.scalars(
        select(CorrelationEdge)
        .where(CorrelationEdge.correlation_id == correlation_id)
        .order_by(CorrelationEdge.id)
    ).all()
    return {
        "correlation": finding.to_dict(),
        "edges": [
            {
                "source_group_id": e.source_group_id,
                "target_group_id": e.target_group_id,
                "relationship_type": e.relationship_type,
                "time_delta_seconds": e.time_delta_seconds,
                "shared_entities": e.shared_entities or [],
                "shared_techniques": e.shared_techniques or [],
                "strength": e.strength,
            }
            for e in edges
        ],
    }


@router.get("/{correlation_id}/groups")
def correlation_groups(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    finding = _fetch(db, correlation_id)
    rows = db.scalars(
        select(CorrelationMember)
        .where(CorrelationMember.correlation_id == correlation_id)
        .order_by(CorrelationMember.id)
    ).all()
    return {
        "correlation_id": correlation_id,
        "member_group_ids": list(finding.member_group_ids or []),
        "total": len(rows),
        "members": [
            {
                "behavior_group_id": m.behavior_group_id,
                "membership_reason": m.membership_reason,
                "role": m.role,
                "created_at": m.created_at.isoformat(),
            }
            for m in rows
        ],
    }


@router.get("/{correlation_id}/alerts")
def correlation_alerts(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    finding = _fetch(db, correlation_id)
    ids = list(finding.member_alert_ids or [])
    rows: list[AlertRecord] = []
    if ids:
        rows = list(
            db.scalars(
                select(AlertRecord)
                .where(AlertRecord.alert_id.in_(ids))
                .order_by(AlertRecord.first_seen)
            ).all()
        )
    return {
        "correlation_id": correlation_id,
        "total": len(rows),
        "alerts": [r.to_dict() for r in rows],
    }


@router.get("/{correlation_id}/evidence")
def correlation_evidence(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    _fetch(db, correlation_id)
    rows = db.scalars(
        select(CorrelationEvidence)
        .where(CorrelationEvidence.correlation_id == correlation_id)
        .order_by(CorrelationEvidence.id)
    ).all()
    return {
        "correlation_id": correlation_id,
        "total": len(rows),
        "evidence": [
            {
                "behavior_group_id": r.behavior_group_id,
                "field": r.field,
                "value": r.value,
                "reason": r.reason,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


@router.get("/{correlation_id}/timeline")
def correlation_timeline(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    """Chronological member progression (spec 5.56)."""
    _gate()
    finding = _fetch(db, correlation_id)
    rows: list[dict] = []
    member_ids = list(finding.member_group_ids or [])
    for group_id in member_ids:
        members = db.scalars(
            select(CorrelationMember).where(
                CorrelationMember.correlation_id == correlation_id,
                CorrelationMember.behavior_group_id == group_id,
            )
        ).all()
        if not members:
            continue
        from backend.aggregation.models import BehaviorGroupRecord

        group = db.scalars(
            select(BehaviorGroupRecord).where(
                BehaviorGroupRecord.behavior_group_id == group_id
            )
        ).first()
        rows.append(
            {
                "time": group.first_seen.isoformat() if group else None,
                "behavior_group_id": group_id,
                "role": members[0].role,
                "membership_reason": members[0].membership_reason,
                "family": "",
            }
        )
    return {"correlation_id": correlation_id, "timeline": rows}


@router.get("/{correlation_id}/graph")
def correlation_graph(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    """The finding as a directed member graph (spec 5.57)."""
    _gate()
    finding = _fetch(db, correlation_id)
    edges = db.scalars(
        select(CorrelationEdge)
        .where(CorrelationEdge.correlation_id == correlation_id)
        .order_by(CorrelationEdge.id)
    ).all()
    nodes = [
        {"behavior_group_id": gid, "role": "member"}
        for gid in (finding.member_group_ids or [])
    ]
    return {
        "correlation_id": correlation_id,
        "nodes": nodes,
        "edges": [
            {
                "source_group_id": e.source_group_id,
                "target_group_id": e.target_group_id,
                "relationship_type": e.relationship_type,
                "strength": e.strength,
            }
            for e in edges
        ],
    }


@router.get("/{correlation_id}/audit")
def correlation_audit(correlation_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    _fetch(db, correlation_id)
    rows = db.scalars(
        select(CorrelationAuditEvent)
        .where(CorrelationAuditEvent.correlation_id == correlation_id)
        .order_by(CorrelationAuditEvent.id)
    ).all()
    return {
        "correlation_id": correlation_id,
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
