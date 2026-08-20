"""Phase 6 risk audit (spec 6.44, 6.70).

Every state-changing operation is recorded with old/new score and state, the
factor or source involved and the model version. Audit rows are append-only
and never deleted (spec 6.72).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.risk.models import EntityRiskV2AuditEvent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def audit(
    db: Session,
    risk_id: str,
    action: str,
    *,
    actor: str = "system",
    details: dict | None = None,
    old_score: float | None = None,
    new_score: float | None = None,
    old_state: str | None = None,
    new_state: str | None = None,
    model_version: str | None = None,
    now: datetime | None = None,
) -> EntityRiskV2AuditEvent:
    row = EntityRiskV2AuditEvent(
        risk_id=risk_id,
        action=action,
        actor=actor,
        details=details,
        old_score=old_score,
        new_score=new_score,
        old_state=old_state,
        new_state=new_state,
        model_version=model_version,
        created_at=now or _utcnow(),
    )
    db.add(row)
    db.flush()
    return row