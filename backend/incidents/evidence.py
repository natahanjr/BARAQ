"""Phase 7 incident evidence handling (spec 7.12, 7.13, 7.42)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select

from backend.incidents.contract import EVIDENCE_SOURCE_TYPES
from backend.incidents.models import IncidentV2Evidence, IncidentV2


def add_evidence(
    db,
    incident_id: str,
    source_type: str,
    source_id: str,
    field: str,
    value: str,
    reason: str,
    observed_at: datetime | None = None,
    actor: str = "system",
) -> IncidentV2Evidence:
    if source_type not in EVIDENCE_SOURCE_TYPES:
        raise ValueError(f"invalid evidence source_type {source_type!r}")
    incident = db.scalars(
        select(IncidentV2).where(IncidentV2.incident_id == incident_id)
    ).first()
    if incident is None:
        raise ValueError(f"unknown incident {incident_id!r}")
    row = IncidentV2Evidence(
        incident_id=incident_id,
        source_type=source_type,
        source_id=source_id,
        field=field,
        value=value,
        reason=reason,
        observed_at=observed_at or datetime.utcnow(),
    )
    db.add(row)
    db.flush()
    return row


def get_evidence(db, incident_id: str) -> list[IncidentV2Evidence]:
    return list(
        db.scalars(
            select(IncidentV2Evidence)
            .where(IncidentV2Evidence.incident_id == incident_id)
            .order_by(IncidentV2Evidence.observed_at)
        ).all()
    )


