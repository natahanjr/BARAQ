"""Phase 7 incident audit trail (spec 7.20)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from backend.incidents.contract import AUDIT_ACTIONS
from backend.incidents.models import IncidentV2AuditEvent, IncidentV2


def audit(
    db,
    incident_id: str,
    action: str,
    actor: str = "system",
    old_value: str | None = None,
    new_value: str | None = None,
    reason: str | None = None,
    now: datetime | None = None,
) -> IncidentV2AuditEvent:
    if action not in AUDIT_ACTIONS:
        raise ValueError(f"unknown audit action {action!r}")
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    row = IncidentV2AuditEvent(
        incident_id=incident_id,
        action=action,
        actor=actor,
        old_value=old_value,
        new_value=new_value,
        reason=reason,
        created_at=now or datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(row)
    db.flush()
    return row


def get_audit(db, incident_id: str) -> list[IncidentV2AuditEvent]:
    return list(
        db.scalars(
            select(IncidentV2AuditEvent)
            .where(IncidentV2AuditEvent.incident_id == incident_id)
            .order_by(IncidentV2AuditEvent.id)
        ).all()
    )


