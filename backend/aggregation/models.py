"""Phase 4 behavior group store (spec 4.3, 4.17, 4.23, 4.30).

Dedicated tables - never the v1 ``alerts``/``incidents``/``entity_risk``/
``risk_events`` stores (spec 4.3). All models subclass
``backend.database.models.Base`` so ``init_db()`` creates them and the test
harness truncates them automatically.

Referential integrity (spec 4.46): every ``alert_id`` references an alert
that exists in ``v2_alerts``; nothing is ever destructively deleted; a
membership row is the only link between alert and group.

Tables:
    behavior_groups             - one behavioral episode (BG-xxxxxx ids)
    behavior_group_members      - alert membership (reason + score)
    behavior_group_evidence     - evidence preserved from member alerts
    behavior_group_audit_events - every state-changing operation
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BehaviorGroupRecord(Base):
    """One behavioral episode (spec 4.2, 4.3)."""

    __tablename__ = "behavior_groups"
    #: Concurrency claim (spec 4.48): at most one live (ACTIVE/QUIET) group
    #: per fingerprint. Workers race to insert; the partial unique index
    #: lets one win via ON CONFLICT DO NOTHING instead of an if-exists/create
    #: race. Closed groups release the fingerprint so the next matching
    #: episode creates a NEW group (spec 4.16).
    __table_args__ = (
        Index(
            "uq_behavior_groups_live_fingerprint",
            "group_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('ACTIVE', 'QUIET')"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Public id, e.g. BG-000001. Independent of the fingerprint.
    behavior_group_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    #: Deterministic grouping key (spec 4.7). Uniqueness is partial: only one
    #: LIVE group may hold a fingerprint at a time - closed groups release it
    #: so the next matching episode creates a NEW group (spec 4.16).
    group_fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(16), index=True, default="ACTIVE")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=0)

    #: Member alert ids in first-seen order (spec 4.2).
    alert_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    host_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    user_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    source_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_tactics: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    #: Aggregated unique observables (spec 4.24).
    observables: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    #: Deterministic grouping confidence (spec 4.27) - NOT a risk score.
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    #: Strongest member severity - never escalated by aggregation (spec 4.28).
    highest_severity: Mapped[str] = mapped_column(String(16), index=True, default="low")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def to_dict(self) -> dict:
        return {
            "behavior_group_id": self.behavior_group_id,
            "group_fingerprint": self.group_fingerprint,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_count": self.alert_count,
            "occurrence_count": self.occurrence_count,
            "alert_ids": list(self.alert_ids or []),
            "host_ids": list(self.host_ids or []),
            "user_ids": list(self.user_ids or []),
            "source_ips": list(self.source_ips or []),
            "mitre_tactics": list(self.mitre_tactics or []),
            "mitre_techniques": list(self.mitre_techniques or []),
            "observables": dict(self.observables or {}),
            "confidence": self.confidence,
            "highest_severity": self.highest_severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


class BehaviorGroupMember(Base):
    """Alert membership (spec 4.17): explainable reason + grouping score."""

    __tablename__ = "behavior_group_members"
    __table_args__ = (
        UniqueConstraint("behavior_group_id", "alert_id", name="uq_group_member_alert"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    behavior_group_id: Mapped[str] = mapped_column(String(32), index=True)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    #: Why this alert belongs here, e.g. "same host + same user + same
    #: source + same behavior family + within 15-minute window".
    membership_reason: Mapped[str] = mapped_column(Text, default="")
    #: Grouping score 0.0-1.0 (spec 4.18) - never a risk score.
    membership_score: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class BehaviorGroupEvidence(Base):
    """Evidence preserved from member alerts (spec 4.23).

    Never reduced to "Multiple alerts detected" - every member alert keeps
    its field/value/reason rows.
    """

    __tablename__ = "behavior_group_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    behavior_group_id: Mapped[str] = mapped_column(String(32), index=True)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    field: Mapped[str] = mapped_column(String(128), default="")
    value: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class BehaviorGroupAuditEvent(Base):
    """Every state-changing operation (spec 4.30)."""

    __tablename__ = "behavior_group_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    behavior_group_id: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
