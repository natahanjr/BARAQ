"""Phase 7 incident management API (spec 7.30-7.33, 7.35, 7.39, 7.48-7.51)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.incidents.audit import audit
from backend.incidents.engine import (
    suppress_incident,
    transition_incident,
)
from backend.incidents.investigation import add_note, assign_incident, get_timeline
from backend.incidents.metrics import incident_metrics
from backend.incidents.models import (
    IncidentV2,
    IncidentV2AlertLink,
    IncidentV2AuditEvent,
    IncidentV2BehaviorGroupLink,
    IncidentV2CorrelationLink,
    IncidentV2Evidence,
    IncidentV2Feedback,
    IncidentV2GraphEdge,
    IncidentV2RiskLink,
)
from backend.security import require_auth

router = APIRouter(
    prefix="/api/incidents-v2",
    tags=["incidents-v2"],
    dependencies=[Depends(require_auth)],
)


def _gate() -> None:
    pass


@router.get("")
def list_incidents(
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    priority: str | None = None,
    assigned_to: str | None = None,
    assigned_team: str | None = None,
    primary_entity_type: str | None = None,
    primary_entity_id: str | None = None,
    correlation_type: str | None = None,
    confidence: float | None = None,
    first_seen_after: datetime | None = None,
    last_seen_before: datetime | None = None,
) -> dict:
    _gate()
    stmt = select(IncidentV2).order_by(IncidentV2.created_at.desc())
    if status is not None:
        stmt = stmt.where(IncidentV2.status == status.upper())
    if severity is not None:
        stmt = stmt.where(IncidentV2.severity == severity.lower())
    if priority is not None:
        stmt = stmt.where(IncidentV2.priority == priority.upper())
    if assigned_to is not None:
        stmt = stmt.where(IncidentV2.assigned_to == assigned_to)
    if assigned_team is not None:
        stmt = stmt.where(IncidentV2.assigned_team == assigned_team)
    if primary_entity_type is not None:
        stmt = stmt.where(IncidentV2.primary_entity_type == primary_entity_type.upper())
    if primary_entity_id is not None:
        stmt = stmt.where(IncidentV2.primary_entity_id == primary_entity_id)
    if confidence is not None:
        stmt = stmt.where(IncidentV2.confidence >= confidence)
    if first_seen_after is not None:
        stmt = stmt.where(IncidentV2.first_seen >= first_seen_after)
    if last_seen_before is not None:
        stmt = stmt.where(IncidentV2.last_seen <= last_seen_before)
    rows = db.scalars(stmt).all()
    return {"count": len(rows), "incidents": [r.to_dict() for r in rows]}


@router.get("/metrics")
def get_metrics(db: Session = Depends(get_db)) -> dict:
    _gate()
    return incident_metrics(db)


@router.get("/metrics/health")
def get_health(db: Session = Depends(get_db)) -> dict:
    _gate()
    metrics = incident_metrics(db)
    return {
        "incident_calculations": metrics["incident_calculations"],
        "incident_creation_failures": metrics["incident_creation_failures"],
        "p50_creation_latency": metrics["creation_latency"]["p50_ms"],
        "p95_creation_latency": metrics["creation_latency"]["p95_ms"],
        "active_incidents": metrics["active_incidents"],
        "overdue_incidents": metrics["overdue_incidents"],
        "model_version": "1.0.0",
        "engine_version": "1.0.0",
    }


@router.get("/feedback-stats")
def feedback_stats(db: Session = Depends(get_db)) -> dict:
    _gate()
    metrics = incident_metrics(db)
    return {
        "total_labels": sum(metrics["feedback"].values()),
        **{k.lower(): v for k, v in metrics["feedback"].items()},
        "sample_size": metrics["sample_size"],
    }


@router.get("/{incident_id}")
def incident_detail(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    row = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")
    payload = row.to_dict()
    payload["related_objects"] = {
        "alerts": [a.alert_id for a in row.alerts],
        "behavior_groups": [g.behavior_group_id for g in row.groups],
        "correlations": [c.correlation_finding_id for c in row.correlations],
        "risks": [r.risk_id for r in row.risks],
    }
    return payload


@router.get("/{incident_id}/alerts")
def incident_alerts(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2AlertLink).where(
            IncidentV2AlertLink.incident_id == incident_id
        )
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "alerts": [r.alert_id for r in rows],
    }


@router.get("/{incident_id}/groups")
def incident_groups(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2BehaviorGroupLink).where(
            IncidentV2BehaviorGroupLink.incident_id == incident_id
        )
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "groups": [r.behavior_group_id for r in rows],
    }


@router.get("/{incident_id}/correlations")
def incident_correlations(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2CorrelationLink).where(
            IncidentV2CorrelationLink.incident_id == incident_id
        )
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "correlations": [r.correlation_finding_id for r in rows],
    }


@router.get("/{incident_id}/risk")
def incident_risk(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2RiskLink).where(IncidentV2RiskLink.incident_id == incident_id)
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "risks": [r.risk_id for r in rows],
    }


@router.get("/{incident_id}/evidence")
def incident_evidence(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2Evidence).where(IncidentV2Evidence.incident_id == incident_id)
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "evidence": [
            {
                "source_type": r.source_type,
                "source_id": r.source_id,
                "field": r.field,
                "value": r.value,
                "reason": r.reason,
                "observed_at": r.observed_at.isoformat() if r.observed_at else None,
            }
            for r in rows
        ],
    }


@router.get("/{incident_id}/timeline")
def incident_timeline(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    return {"incident_id": incident_id, "timeline": get_timeline(db, incident_id)}


@router.get("/{incident_id}/audit")
def incident_audit(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    rows = db.scalars(
        select(IncidentV2AuditEvent)
        .where(IncidentV2AuditEvent.incident_id == incident_id)
        .order_by(IncidentV2AuditEvent.id)
    ).all()
    return {
        "incident_id": incident_id,
        "count": len(rows),
        "events": [
            {
                "action": r.action,
                "actor": r.actor,
                "old_value": r.old_value,
                "new_value": r.new_value,
                "reason": r.reason,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.get("/{incident_id}/graph")
def incident_graph(incident_id: str, db: Session = Depends(get_db)) -> dict:
    _gate()
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")
    rows = db.scalars(
        select(IncidentV2GraphEdge).where(
            IncidentV2GraphEdge.incident_id == incident_id
        )
    ).all()
    nodes = [{"id": incident_id, "kind": "INCIDENT", "label": incident.title}]
    edges = [
        {
            "from": r.source_id,
            "to": r.target_id,
            "relationship_type": r.relationship_type,
            "reason": r.reason,
        }
        for r in rows
    ]
    return {"incident_id": incident_id, "nodes": nodes, "edges": edges}


@router.post("/{incident_id}/transition")
def post_transition(
    incident_id: str,
    db: Session = Depends(get_db),
    status: str = Query(...),
    reason: str | None = Query(default=None),
    actor: str = Query(default="system"),
) -> dict:
    try:
        result = transition_incident(
            db, incident_id, status.upper(), actor=actor, reason=reason
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


@router.post("/{incident_id}/notes")
def post_note(
    incident_id: str,
    db: Session = Depends(get_db),
    author: str = Query(...),
    content: str = Query(...),
) -> dict:
    try:
        note = add_note(db, incident_id, author, content)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"note_id": note.note_id, "incident_id": incident_id}


@router.post("/{incident_id}/assign")
def post_assign(
    incident_id: str,
    db: Session = Depends(get_db),
    assigned_to: str | None = Query(default=None),
    assigned_team: str | None = Query(default=None),
    actor: str = Query(default="system"),
) -> dict:
    try:
        return assign_incident(db, incident_id, assigned_to, assigned_team, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/{incident_id}/suppress")
def post_suppress(
    incident_id: str,
    db: Session = Depends(get_db),
    reason: str = Query(...),
    scope: str = Query(...),
    expires_in_days: int = Query(default=30, ge=1, le=90),
    actor: str = Query(default="system"),
) -> dict:
    expires_at = datetime.now(UTC).replace(tzinfo=None) + timedelta(
        days=expires_in_days
    )
    try:
        row = suppress_incident(db, incident_id, reason, scope, expires_at, actor)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "suppression_id": row.id,
        "incident_id": incident_id,
        "expires_at": row.expires_at.isoformat(),
    }


@router.post("/{incident_id}/feedback")
def post_feedback(
    incident_id: str,
    db: Session = Depends(get_db),
    analyst: str = Query(...),
    feedback_type: str = Query(...),
    reason: str | None = Query(default=None),
) -> dict:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise HTTPException(status_code=404, detail=f"unknown incident {incident_id}")
    row = IncidentV2Feedback(
        incident_id=incident_id,
        analyst=analyst,
        feedback_type=feedback_type.upper(),
        reason=reason,
    )
    db.add(row)
    db.flush()
    audit(
        db,
        incident_id,
        "INCIDENT_FEEDBACK_ADDED",
        actor=analyst,
        new_value=feedback_type.upper(),
        now=datetime.now(UTC).replace(tzinfo=None),
    )
    return {"feedback_id": row.id, "incident_id": incident_id}
