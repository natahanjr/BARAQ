"""Alert audit trail (spec 3.27, 3.35).

Every state-changing operation on an alert creates an
``alert_audit_events`` row: CREATED, OCCURRENCE, ACKNOWLEDGED, ASSIGNED,
IN_PROGRESS, RESOLVED, CLOSED, SUPPRESSED, REOPENED, FEEDBACK.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.alerting.models import AlertAuditEvent


def record(
    db: Session,
    alert_id: str,
    action: str,
    previous_status: str = "",
    new_status: str = "",
    actor: str = "system",
    details: dict | None = None,
) -> AlertAuditEvent:
    event = AlertAuditEvent(
        alert_id=alert_id,
        action=action,
        previous_status=previous_status,
        new_status=new_status,
        actor=actor,
        details=details,
    )
    db.add(event)
    db.flush()
    return event


def for_alert(db: Session, alert_id: str) -> list[AlertAuditEvent]:
    from sqlalchemy import select

    return list(
        db.scalars(
            select(AlertAuditEvent)
            .where(AlertAuditEvent.alert_id == alert_id)
            .order_by(AlertAuditEvent.created_at, AlertAuditEvent.id)
        ).all()
    )