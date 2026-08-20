"""Phase 7 incident models (spec 7.1, 7.12-7.14, 7.18, 7.20, 7.21, 7.32-7.34, 7.38, 7.42, 7.45)."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, DeclarativeBase

from backend.database.models import Base
from backend.incidents.contract import (
    AUDIT_ACTIONS,
    EVIDENCE_SOURCE_TYPES,
    GRAPH_RELATIONSHIP_TYPES,
    INCIDENT_PRIORITIES,
    INCIDENT_SEVERITIES,
    INCIDENT_STATES,
)


class IncidentV2(Base):
    __tablename__ = "incidents_v2"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        Enum(*INCIDENT_STATES, name="incident_status"), default="NEW", index=True
    )
    priority: Mapped[str] = mapped_column(
        Enum(*INCIDENT_PRIORITIES, name="incident_priority"), default="P3", index=True
    )
    severity: Mapped[str] = mapped_column(
        Enum(*INCIDENT_SEVERITIES, name="incident_severity"), default="medium", index=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    confidence_factors: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    primary_entity_type: Mapped[str] = mapped_column(String(16), index=True)
    primary_entity_id: Mapped[str] = mapped_column(String(256), index=True)
    entity_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    observables: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    investigation_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assigned_team: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    source_type: Mapped[str] = mapped_column(String(32), default="CORRELATION")
    source_id: Mapped[str] = mapped_column(String(128), index=True)
    incident_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    model_version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    policy_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    created_by: Mapped[str] = mapped_column(String(128), default="system")
    updated_by: Mapped[str] = mapped_column(String(128), default="system")

    suppression_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suppression_scope: Mapped[str | None] = mapped_column(String(64), nullable=True)
    suppression_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    suppression_created_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    alerts: Mapped[list["IncidentV2AlertLink"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    groups: Mapped[list["IncidentV2BehaviorGroupLink"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    correlations: Mapped[list["IncidentV2CorrelationLink"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    risks: Mapped[list["IncidentV2RiskLink"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    evidence: Mapped[list["IncidentV2Evidence"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    audit: Mapped[list["IncidentV2AuditEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    notes: Mapped[list["IncidentV2Note"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    feedback: Mapped[list["IncidentV2Feedback"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )
    graph_edges: Mapped[list["IncidentV2GraphEdge"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", passive_deletes=True
    )

    __table_args__ = (
        Index("ix_incident_status_priority", "status", "priority"),
        Index("ix_incident_primary_entity", "primary_entity_type", "primary_entity_id"),
        Index("ix_incident_created_at", "created_at"),
        Index("ix_incident_fingerprint", "fingerprint"),
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "priority": self.priority,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_factors": self.confidence_factors,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "primary_entity_type": self.primary_entity_type,
            "primary_entity_id": self.primary_entity_id,
            "entity_ids": self.entity_ids,
            "observables": self.observables,
            "investigation_state": self.investigation_state,
            "assigned_to": self.assigned_to,
            "assigned_team": self.assigned_team,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "incident_version": self.incident_version,
            "model_version": self.model_version,
            "policy_id": self.policy_id,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "suppression_reason": self.suppression_reason,
            "suppression_scope": self.suppression_scope,
            "suppression_expires_at": self.suppression_expires_at.isoformat() if self.suppression_expires_at else None,
            "suppression_created_by": self.suppression_created_by,
        }


class IncidentV2AlertLink(Base):
    __tablename__ = "incident_v2_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    alert_id: Mapped[str] = mapped_column(String(64), index=True)
    membership_reason: Mapped[str] = mapped_column(String(255), default="alert evidence")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="alerts")
    __table_args__ = (UniqueConstraint("incident_id", "alert_id", name="uq_incident_v2_alert"),)


class IncidentV2BehaviorGroupLink(Base):
    __tablename__ = "incident_v2_behavior_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    behavior_group_id: Mapped[str] = mapped_column(String(64), index=True)
    membership_reason: Mapped[str] = mapped_column(String(255), default="behavior group evidence")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="groups")
    __table_args__ = (UniqueConstraint("incident_id", "behavior_group_id", name="uq_incident_v2_group"),)


class IncidentV2CorrelationLink(Base):
    __tablename__ = "incident_v2_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    correlation_finding_id: Mapped[str] = mapped_column(String(64), index=True)
    membership_reason: Mapped[str] = mapped_column(String(255), default="correlation finding")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="correlations")
    __table_args__ = (UniqueConstraint("incident_id", "correlation_finding_id", name="uq_incident_v2_correlation"),)


class IncidentV2RiskLink(Base):
    __tablename__ = "incident_v2_risk_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    risk_id: Mapped[str] = mapped_column(String(32), index=True)
    membership_reason: Mapped[str] = mapped_column(String(255), default="entity risk context")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="risks")
    __table_args__ = (UniqueConstraint("incident_id", "risk_id", name="uq_incident_v2_risk"),)


class IncidentV2Evidence(Base):
    __tablename__ = "incident_v2_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    source_id: Mapped[str] = mapped_column(String(128), index=True)
    field: Mapped[str] = mapped_column(String(64))
    value: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    added_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="evidence")
    __table_args__ = (
        Index("ix_incident_v2_evidence_source", "incident_id", "source_type", "source_id"),
    )


class IncidentV2AuditEvent(Base):
    __tablename__ = "incident_v2_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128))
    old_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    new_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    incident: Mapped["IncidentV2"] = relationship(back_populates="audit")
    __table_args__ = (Index("ix_incident_v2_audit_action", "incident_id", "action"),)


class IncidentV2Note(Base):
    __tablename__ = "incident_v2_notes"

    note_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    author: Mapped[str] = mapped_column(String(128))
    content: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="notes")


class IncidentV2Feedback(Base):
    __tablename__ = "incident_v2_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    analyst: Mapped[str] = mapped_column(String(128))
    feedback_type: Mapped[str] = mapped_column(String(32), index=True)
    reason: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="feedback")
    __table_args__ = (Index("ix_incident_v2_feedback_type", "incident_id", "feedback_type"),)


class IncidentV2GraphEdge(Base):
    __tablename__ = "incident_v2_graph_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str] = mapped_column(
        ForeignKey("incidents_v2.incident_id", ondelete="CASCADE"), index=True
    )
    relationship_type: Mapped[str] = mapped_column(String(64), index=True)
    source_id: Mapped[str] = mapped_column(String(128))
    target_id: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    incident: Mapped["IncidentV2"] = relationship(back_populates="graph_edges")
    __table_args__ = (Index("ix_incident_v2_graph_rel", "incident_id", "relationship_type"),)


class IncidentV2Suppression(Base):
    __tablename__ = "incident_v2_suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[str | None] = mapped_column(
        String(32), ForeignKey("incidents_v2.incident_id", ondelete="SET NULL"),
        nullable=True, index=True
    )
    fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(String(255))
    scope: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
