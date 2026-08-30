"""Phase 6 entity risk store (spec 6.3, 6.70-6.72).

Dedicated tables - never the v1 ``entity_risk``/``risk_events`` stores and
never ``v2_alerts``/``behavior_groups``/``correlation_findings`` (risk
references those; it never rewrites them - spec 6.61). The v1 schema already
owns the ``entity_risk`` and ``entity_risk_events`` names, so the Phase 6
tables follow the established v2 naming convention (``v2_alerts``,
``v2_events``) and live under ``entity_risk_v2*``.

Tables:
    entity_risk_v2           - one live risk record per entity (ER-xxxxxx)
    entity_risk_v2_events    - evidence ingest log (one row per evidence)
    entity_risk_v2_factors   - every contribution with full provenance
    entity_risk_v2_snapshots - point-in-time scores; never overwritten
    entity_risk_v2_audit     - every state-changing operation

Every child table carries foreign keys (spec 6.71); no destructive deletion
(spec 6.72); factors reference their alert/group/correlation source rows
without owning them.
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
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class EntityRiskV2(Base):
    """One live entity risk record (spec 6.4)."""

    __tablename__ = "entity_risk_v2"
    #: At most one record per entity (spec 6.35).
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", name="uq_risk_v2_entity"),
        Index("ix_risk_v2_entity_type", "entity_type"),
        Index("ix_risk_v2_entity_id", "entity_id"),
        Index("ix_risk_v2_score", "score"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Public id, e.g. ER-000001.
    risk_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(16), index=True)
    entity_id: Mapped[str] = mapped_column(String(256), index=True)
    entity_name: Mapped[str] = mapped_column(String(256), default="")

    #: Deterministic accumulated score (0..100) - never severity, never
    #: confidence of compromise (spec 6.83).
    score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), index=True, default="MINIMAL")
    state: Mapped[str] = mapped_column(String(16), index=True, default="NORMAL")
    #: Share of the current score resting on direct evidence (spec 6.4).
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    #: Descriptive trend (spec 6.24) - never a factor.
    trend: Mapped[str] = mapped_column(String(16), default="UNKNOWN")

    peak_score: Mapped[float] = mapped_column(Float, default=0.0)
    peak_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_calculated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    active_factor_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    group_count: Mapped[int] = mapped_column(Integer, default=0)
    correlation_count: Mapped[int] = mapped_column(Integer, default=0)

    risk_model_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    def to_dict(self) -> dict:
        return {
            "risk_id": self.risk_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "score": self.score,
            "severity": self.severity,
            "state": self.state,
            "confidence": self.confidence,
            "trend": self.trend,
            "peak_score": self.peak_score,
            "peak_at": self.peak_at.isoformat() if self.peak_at else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "last_calculated_at": (
                self.last_calculated_at.isoformat() if self.last_calculated_at else None
            ),
            "active_factor_count": self.active_factor_count,
            "evidence_count": self.evidence_count,
            "alert_count": self.alert_count,
            "group_count": self.group_count,
            "correlation_count": self.correlation_count,
            "risk_model_version": self.risk_model_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class EntityRiskV2Event(Base):
    """Evidence ingest log (spec 6.1): one row per processed evidence."""

    __tablename__ = "entity_risk_v2_events"
    __table_args__ = (
        Index("ix_risk_v2_ev_source", "source_type", "source_id"),
        UniqueConstraint(
            "risk_id",
            "source_type",
            "source_id",
            name="uq_risk_v2_ev_source",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("entity_risk_v2.risk_id"),
        index=True,
    )
    evidence_kind: Mapped[str] = mapped_column(String(32), index=True)
    source_type: Mapped[str] = mapped_column(String(64), index=True)
    source_id: Mapped[str] = mapped_column(String(128), index=True)
    source_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    summary: Mapped[str] = mapped_column(Text, default="")
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class EntityRiskV2Factor(Base):
    """One contribution with full provenance (spec 6.42, 6.9)."""

    __tablename__ = "entity_risk_v2_factors"
    __table_args__ = (
        UniqueConstraint(
            "risk_id",
            "factor_id",
            "source_type",
            "source_id",
            name="uq_risk_v2_factor_source",
        ),
        Index("ix_risk_v2_factor_type", "factor_type"),
        Index("ix_risk_v2_factor_src", "source_type"),
        Index("ix_risk_v2_factor_expires", "expires_at"),
        Index("ix_risk_v2_factor_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("entity_risk_v2.risk_id"),
        index=True,
    )
    factor_id: Mapped[str] = mapped_column(String(64), index=True)
    factor_type: Mapped[str] = mapped_column(String(32), index=True)
    factor_version: Mapped[str] = mapped_column(String(16), default="1.0")

    #: Which evidence this factor comes from (spec 6.42).
    source_type: Mapped[str] = mapped_column(String(64))
    source_id: Mapped[str] = mapped_column(String(128))
    value: Mapped[float] = mapped_column(Float, default=0.0)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    contribution: Mapped[float] = mapped_column(Float, default=0.0)

    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    #: DIRECT evidence or CONTEXTUAL propagation (spec 6.81).
    origin: Mapped[str] = mapped_column(String(16), default="DIRECT")
    propagation_from: Mapped[str | None] = mapped_column(String(128), nullable=True)
    relationship_type: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expired_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class EntityRiskV2Snapshot(Base):
    """Point-in-time score (spec 6.23). Never overwritten, never deleted."""

    __tablename__ = "entity_risk_v2_snapshots"
    __table_args__ = (Index("ix_risk_v2_snap_risk", "risk_id", "captured_at"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("entity_risk_v2.risk_id"),
        index=True,
    )
    score: Mapped[float] = mapped_column(Float, default=0.0)
    severity: Mapped[str] = mapped_column(String(16), default="MINIMAL")
    state: Mapped[str] = mapped_column(String(16), default="NORMAL")
    trend: Mapped[str] = mapped_column(String(16), default="UNKNOWN")
    factor_count: Mapped[int] = mapped_column(Integer, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_model_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class EntityRiskV2AuditEvent(Base):
    """Every state-changing operation (spec 6.44, 6.70)."""

    __tablename__ = "entity_risk_v2_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("entity_risk_v2.risk_id"),
        index=True,
    )
    action: Mapped[str] = mapped_column(String(32), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    old_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    new_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    old_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
