"""Phase 7 incident investigation operations (spec 7.16-7.18, 7.19, 7.17)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from backend.incidents.audit import audit
from backend.incidents.lifecycle import is_terminal
from backend.incidents.models import IncidentV2, IncidentV2Note


def add_note(
    db,
    incident_id: str,
    author: str,
    content: str,
    note_id: str | None = None,
) -> IncidentV2Note:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    if is_terminal(incident.status):
        raise ValueError(f"cannot add note to terminal incident {incident.status!r}")
    if note_id is None:
        note_id = (
            f"NOTE-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}-{incident_id[-4:]}"
        )
    row = IncidentV2Note(
        note_id=note_id,
        incident_id=incident_id,
        author=author,
        content=content,
    )
    db.add(row)
    db.flush()
    audit(
        db,
        incident_id,
        "INCIDENT_NOTE_ADDED",
        actor=author,
        new_value=note_id,
        reason="analyst note",
        now=datetime.now(UTC),
    )
    incident.updated_at = datetime.now(UTC)
    incident.updated_by = author
    db.flush()
    return row


def assign_incident(
    db,
    incident_id: str,
    assigned_to: str | None,
    assigned_team: str | None,
    actor: str = "system",
) -> dict:
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    old_to = incident.assigned_to
    old_team = incident.assigned_team
    incident.assigned_to = assigned_to
    incident.assigned_team = assigned_team
    incident.assigned_at = datetime.now(UTC)
    incident.updated_at = datetime.now(UTC)
    incident.updated_by = actor
    db.flush()
    if old_to != assigned_to:
        action = "INCIDENT_ASSIGNED" if assigned_to else "INCIDENT_UNASSIGNED"
        audit(
            db,
            incident_id,
            action,
            actor=actor,
            old_value=old_to,
            new_value=assigned_to,
            now=datetime.now(UTC),
        )
    if old_team != assigned_team:
        audit(
            db,
            incident_id,
            "INCIDENT_TEAM_ASSIGNED",
            actor=actor,
            old_value=old_team,
            new_value=assigned_team,
            now=datetime.now(UTC),
        )
    return {"assigned_to": assigned_to, "assigned_team": assigned_team}


def get_timeline(db, incident_id: str) -> list[dict]:
    from backend.incidents.models import (
        IncidentV2AuditEvent,
        IncidentV2Note,
    )

    events: list[dict] = []
    for row in db.scalars(
        select(IncidentV2AuditEvent)
        .where(IncidentV2AuditEvent.incident_id == incident_id)
        .order_by(IncidentV2AuditEvent.id)
    ).all():
        events.append(
            {
                "type": row.action,
                "actor": row.actor,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "reason": row.reason,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
    for row in db.scalars(
        select(IncidentV2Note)
        .where(IncidentV2Note.incident_id == incident_id)
        .order_by(IncidentV2Note.note_id)
    ).all():
        events.append(
            {
                "type": "note_added",
                "actor": row.author,
                "note_id": row.note_id,
                "content": row.content,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
        )
    events.sort(key=lambda e: e.get("created_at") or "")
    return events
