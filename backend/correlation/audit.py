"""Phase 5 correlation audit (spec 5.63)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.correlation.models import CorrelationAuditEvent


def record(
    db: Session,
    *,
    correlation_id: str,
    action: str,
    actor: str = "system",
    details: dict | None = None,
    now: datetime | None = None,
) -> CorrelationAuditEvent:
    event = CorrelationAuditEvent(
        correlation_id=correlation_id,
        action=action,
        actor=actor,
        details=details or {},
        created_at=now or datetime.now(UTC),
    )
    db.add(event)
    return event
