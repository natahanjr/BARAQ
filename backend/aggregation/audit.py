"""Phase 4 group audit (spec 4.30)."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.aggregation.models import BehaviorGroupAuditEvent


def record(
    db: Session,
    *,
    group_id: str,
    action: str,
    actor: str = "system",
    details: dict | None = None,
    now: datetime | None = None,
) -> BehaviorGroupAuditEvent:
    event = BehaviorGroupAuditEvent(
        behavior_group_id=group_id,
        action=action,
        actor=actor,
        details=details or {},
        created_at=now or datetime.now(timezone.utc),
    )
    db.add(event)
    return event