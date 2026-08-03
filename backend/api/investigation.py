"""Investigation API - attack chain reconstruction for an alert."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import Alert, AlertEventLink, NetworkConnection, NormalizedEvent

router = APIRouter(prefix="/api/investigation", tags=["investigation"])


def _related_events(db: Session, alert: Alert, window_minutes: int = 30) -> list[dict]:
    """All events around the alert's evidence (before/after the first link)."""
    link = db.scalars(
        select(AlertEventLink)
        .where(AlertEventLink.alert_id == alert.id)
        .order_by(AlertEventLink.event_id)
        .limit(1)
    ).first()
    if not link:
        return []

    from datetime import timedelta

    anchor = db.get(NormalizedEvent, link.event_id)
    if not anchor:
        return []
    start = anchor.timestamp - timedelta(minutes=window_minutes)
    end = anchor.timestamp + timedelta(minutes=window_minutes)
    rows = db.scalars(
        select(NormalizedEvent)
        .where(NormalizedEvent.timestamp.between(start, end))
        .order_by(NormalizedEvent.timestamp)
    ).all()
    return [e.to_dict() for e in rows[:200]]


def _attack_chain(db: Session, alert: Alert) -> list[dict]:
    """Rebuild a kill-chain narrative from linked evidence events."""
    chain = []
    steps: dict[str, list[str]] = {}
    for link in sorted(alert.events, key=lambda l: l.event_id):
        event = link.event
        step = {
            4625: "Credential probing",
            4624: "Access granted",
            4720: "Account creation",
            4732: "Privilege assignment",
            4672: "Privileged logon",
            4104: "Script execution",
            7045: "Persistence installed",
            4698: "Scheduled persistence",
        }.get(event.event_id, "Observation")
        steps.setdefault(step, [])
        steps[step].append(
            f"Event {event.event_id} {event.timestamp.isoformat()} "
            f"user={event.user} | {event.message[:120]}"
        )

    for step_name, lines in steps.items():
        chain.append({"step": step_name, "details": lines})
    if not chain:
        chain.append({"step": "Evidence", "details": [alert.evidence]})
    return chain


@router.get("/alert/{alert_id}")
def investigate(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    evidence_events = [link.event.to_dict() for link in alert.events]
    related = _related_events(db, alert)
    chain = _attack_chain(db, alert)

    # Network context: connections around the alert window
    if alert.mitre_id == "T1046":
        conns = db.scalars(
            select(NetworkConnection).order_by(NetworkConnection.observed_at.desc()).limit(50)
        ).all()
        network = [c.to_dict() for c in conns]
    else:
        network = []

    return {
        "alert": alert.to_dict(include_events=True),
        "evidence_events": evidence_events,
        "related_events": related,
        "attack_chain": chain,
        "network_context": network,
        "summary": (
            f"Attack chain for {alert.name} ({alert.mitre_id} / {alert.mitre_tactic}): "
            f"{len(evidence_events)} evidence events, {len(related)} related events "
            f"across {len(chain)} kill-chain step(s)."
        ),
    }
