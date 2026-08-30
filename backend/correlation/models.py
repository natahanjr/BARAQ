"""Phase 5 correlation store (spec 5.2, 5.64).

Dedicated tables - never the v1 stores, never ``v2_alerts`` and never
``behavior_groups`` (correlation references groups; it does not rewrite
them - spec 5.68). Every child table carries foreign keys (spec 5.64), so
orphaned records are impossible; no destructive deletion, audit is the only
removal path (spec 5.65).

Tables:
    correlation_findings      - one correlated behavioral sequence (CF-xxxxxx)
    correlation_members       - member behavior groups (reason + role)
    correlation_edges         - ordered relationship between two member groups
    correlation_evidence      - evidence preserved from groups/rules
    correlation_audit_events  - every state-changing operation
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
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
    return datetime.now(UTC)


class CorrelationFindingRecord(Base):
    """One correlated behavioral sequence (spec 5.3)."""

    __tablename__ = "correlation_findings"
    #: Concurrency claim (spec 5.35): at most one live (NEW/ACTIVE/QUIET)
    #: finding per fingerprint. Closed findings release the fingerprint so
    #: the next matching sequence creates a NEW finding (spec 5.32).
    __table_args__ = (
        Index(
            "uq_correlation_live_fingerprint",
            "fingerprint",
            unique=True,
            postgresql_where=text("status IN ('NEW', 'ACTIVE', 'QUIET')"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Public id, e.g. CF-000001. Independent of the fingerprint.
    correlation_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    #: Deterministic grouping key (spec 5.6).
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(16), index=True, default="NEW")
    correlation_type: Mapped[str] = mapped_column(String(32), index=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    #: Member group ids in sequence order (spec 5.3).
    member_group_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    member_alert_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    entities: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    hosts: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    users: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    source_ips: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_tactics: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    observables: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    #: Deterministic correlation confidence (spec 5.23) - never risk.
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    #: Strongest member group severity - never escalated (spec 5.25).
    highest_severity: Mapped[str] = mapped_column(String(16), index=True, default="low")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def to_dict(self) -> dict:
        return {
            "correlation_id": self.correlation_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "correlation_type": self.correlation_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "member_group_ids": list(self.member_group_ids or []),
            "member_alert_ids": list(self.member_alert_ids or []),
            "entities": list(self.entities or []),
            "hosts": list(self.hosts or []),
            "users": list(self.users or []),
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


class CorrelationMember(Base):
    """Member behavior group (spec 5.19): explainable membership."""

    __tablename__ = "correlation_members"
    __table_args__ = (
        UniqueConstraint(
            "correlation_id", "behavior_group_id", name="uq_corr_member_group"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("correlation_findings.correlation_id"),
        index=True,
    )
    behavior_group_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("behavior_groups.behavior_group_id"),
        index=True,
    )
    #: Why this group belongs to the finding, e.g. "rule R003: external
    #: access -> lateral movement, same user, within 60-minute window".
    membership_reason: Mapped[str] = mapped_column(Text, default="")
    role: Mapped[str] = mapped_column(String(64), default="member")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class CorrelationEdge(Base):
    """Ordered relationship between two member groups (spec 5.19, 5.47)."""

    __tablename__ = "correlation_edges"
    __table_args__ = (
        UniqueConstraint(
            "correlation_id",
            "source_group_id",
            "target_group_id",
            "relationship_type",
            name="uq_corr_edge_pair",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("correlation_findings.correlation_id"),
        index=True,
    )
    source_group_id: Mapped[str] = mapped_column(String(32), index=True)
    target_group_id: Mapped[str] = mapped_column(String(32), index=True)
    relationship_type: Mapped[str] = mapped_column(String(32), index=True)
    time_delta_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    shared_entities: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    shared_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    strength: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class CorrelationEvidence(Base):
    """Evidence preserved from the correlated groups (spec 5.29)."""

    __tablename__ = "correlation_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("correlation_findings.correlation_id"),
        index=True,
    )
    behavior_group_id: Mapped[str] = mapped_column(String(32), index=True)
    field: Mapped[str] = mapped_column(String(128), default="")
    value: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(String(256), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class CorrelationAuditEvent(Base):
    """Every state-changing operation (spec 5.63)."""

    __tablename__ = "correlation_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlation_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("correlation_findings.correlation_id"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
