"""Incident (case) management API.

Incidents group related alerts into trackable cases with severity, status,
ownership, MITRE mapping and an analyst comment timeline.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    Incident,
    IncidentAlertLink,
    IncidentComment,
)
from backend.security import actor_name, tenant_scope, require_admin, require_auth

logger = logging.getLogger("baraq.api.incidents")

router = APIRouter(
    prefix="/api/incidents",
    tags=["incidents"],
    dependencies=[Depends(require_auth)],
)


class IncidentStatus(str, Enum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class IncidentSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=256)
    description: str = Field(default="", max_length=5000)
    severity: IncidentSeverity = IncidentSeverity.high
    owner: str = Field(default="", max_length=128)
    host: str = Field(default="", max_length=128)
    alert_ids: list[int] = Field(default_factory=list)
    mitre_id: str = Field(default="", max_length=16)
    mitre_name: str = Field(default="", max_length=128)


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=256)
    description: str | None = Field(default=None, max_length=5000)
    severity: IncidentSeverity | None = None
    status: IncidentStatus | None = None
    owner: str | None = Field(default=None, max_length=128)
    host: str | None = Field(default=None, max_length=128)


class IncidentCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    kind: str = Field(default="comment", pattern="^(comment|action|status)$")


class IncidentLinkAlerts(BaseModel):
    alert_ids: list[int] = Field(default_factory=list)


def _publish_incident(incident: Incident) -> None:
    """Push an incident update to realtime dashboard clients (best-effort)."""
    try:
        from backend.realtime import publish_incident

        publish_incident(incident.to_dict())
    except Exception:  # noqa: BLE001 - realtime must never break incidents
        logger.debug("Failed to publish incident #%s over realtime", incident.id, exc_info=True)


def _with_links(stmt):
    """Eager-load alert links (with their alert) and comments in one pass."""
    return stmt.options(
        selectinload(Incident.alerts).selectinload(IncidentAlertLink.alert),
        selectinload(Incident.comments),
    )


@router.get("")
def list_incidents(
    request: Request,
    status: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = _with_links(select(Incident).order_by(Incident.created_at.desc()).limit(limit))
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    if status:
        stmt = stmt.where(Incident.status == status.value)
    if severity:
        stmt = stmt.where(Incident.severity == severity.value)
    rows = db.scalars(stmt).all()
    return {"items": [i.to_dict() for i in rows]}


@router.get("/{incident_id}")
def get_incident(incident_id: int, request: Request, db: Session = Depends(get_db)):
    scope = tenant_scope(request)
    stmt = _with_links(select(Incident)).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident.to_dict(include_links=True)


@router.post("", dependencies=[Depends(require_admin)])
def create_incident(
    body: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    actor = actor_name(request)
    incident = Incident(
        title=body.title,
        description=body.description,
        severity=body.severity.value,
        owner=body.owner,
        host=body.host,
        org="",
        mitre_id=body.mitre_id,
        mitre_name=body.mitre_name,
        opened_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    db.flush()

    for alert_id in body.alert_ids:
        alert = db.get(Alert, alert_id)
        if alert:
            db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert_id))
            incident.org = alert.org or incident.org

    db.add(IncidentComment(
        incident_id=incident.id,
        author=actor,
        body=f"Incident created by {actor}",
        kind="status",
    ))

    linked_alerts = [db.get(Alert, a) for a in body.alert_ids]
    max_risk = max((a.risk_score or 0.0) for a in linked_alerts if a) if linked_alerts else 0.0
    incident.risk_score = max_risk
    incident.risk_level = (
        "CRITICAL" if max_risk >= 80 else "HIGH" if max_risk >= 60 else "MEDIUM"
    )

    db.commit()
    db.refresh(incident)
    log_action(db, actor, "incident.create", "incident", incident.id,
               f"Created incident '{body.title}'", client_ip(request))
    _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.patch("/{incident_id}", dependencies=[Depends(require_admin)])
def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    actor = actor_name(request)
    changes: list[str] = []

    for field, value in body.model_dump(exclude_unset=True).items():
        if value is None:
            continue
        if isinstance(value, Enum):
            value = value.value
        if getattr(incident, field) != value:
            changes.append(f"{field}->{value}")
            setattr(incident, field, value)

    if body.status is not None:
        now = datetime.now(timezone.utc)
        if body.status.value in ("resolved", "closed") and not incident.resolved_at:
            incident.resolved_at = now
        if body.status.value == "closed" and not incident.closed_at:
            incident.closed_at = now
        if body.status.value in ("open", "investigating", "contained"):
            incident.closed_at = None

    if changes:
        db.add(IncidentComment(
            incident_id=incident.id,
            author=actor,
            body=", ".join(changes),
            kind="status",
        ))
        db.commit()
        db.refresh(incident)
        log_action(db, actor, "incident.update", "incident", incident.id,
                   "Updated: " + "; ".join(changes), client_ip(request))
        _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.post("/{incident_id}/alerts", dependencies=[Depends(require_admin)])
def link_alerts(
    incident_id: int,
    body: IncidentLinkAlerts,
    request: Request,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")

    linked: list[int] = []
    existing = {l.alert_id for l in incident.alerts}
    for alert_id in body.alert_ids:
        if alert_id in existing:
            continue
        alert = db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(404, f"Alert {alert_id} not found")
        db.add(IncidentAlertLink(incident_id=incident_id, alert_id=alert_id))
        if not incident.org:
            incident.org = alert.org
        linked.append(alert_id)

    actor = actor_name(request)
    if linked:
        db.add(IncidentComment(
            incident_id=incident_id,
            author=actor,
            body=f"Linked alerts: {', '.join(map(str, linked))}",
            kind="action",
        ))
        db.commit()
        db.refresh(incident)
        log_action(db, actor, "incident.link_alerts", "incident", incident_id,
                   f"Linked alerts {linked}", client_ip(request))
        _publish_incident(incident)
    return incident.to_dict(include_links=True)


@router.post("/{incident_id}/comments")
def add_comment(
    incident_id: int,
    body: IncidentCommentCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Incident).where(Incident.id == incident_id)
    if scope is not None:
        stmt = stmt.where(Incident.org == scope)
    incident = db.scalars(stmt).first()
    if not incident:
        raise HTTPException(404, "Incident not found")
    comment = IncidentComment(
        incident_id=incident_id,
        author=actor_name(request),
        body=body.body,
        kind=body.kind,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment.to_dict()
