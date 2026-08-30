"""Phase 3 alert store (spec 3.32-3.35).

Dedicated v2 tables - deliberately NOT the v1 ``alerts`` table, which is
mixed with incident/risk/playbook behavior. All models subclass
``backend.database.models.Base`` so ``init_db()`` creates them and the
test harness truncates them automatically.

Tables:
    v2_alerts                 - the analyst-facing alert (ALR-xxxx ids)
    alert_occurrences         - one row per merged detection occurrence
    alert_feedback            - structured analyst feedback
    alert_audit_events        - every state-changing operation
    alert_suppression_rules   - auditable, expiring suppression policies
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AlertRecord(Base):
    """One v2 alert (spec 3.3, 3.32). Table name ``v2_alerts`` avoids the
    v1 ``alerts`` table entirely."""

    __tablename__ = "v2_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Public id, e.g. ALR-000001. Independent of the fingerprint.
    alert_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    #: Deterministic dedup key (spec 3.7).
    alert_fingerprint: Mapped[str] = mapped_column(String(64), index=True)

    detector_id: Mapped[str] = mapped_column(String(16), index=True)
    detector_version: Mapped[str] = mapped_column(String(16), default="1.0.0")

    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    status: Mapped[str] = mapped_column(String(16), index=True, default="OPEN")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)

    host_id: Mapped[str] = mapped_column(String(128), default="")
    host_name: Mapped[str] = mapped_column(String(128), index=True, default="")
    user_id: Mapped[str] = mapped_column(String(128), default="")
    username: Mapped[str] = mapped_column(String(128), index=True, default="")
    source_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    destination_ip: Mapped[str] = mapped_column(String(64), default="")

    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    mitre_technique: Mapped[str] = mapped_column(String(16), index=True, default="")

    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    observables: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    #: detection_ids merged into this alert (spec 3.8).
    detection_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    assigned_to: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    assigned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    feedback: Mapped[str | None] = mapped_column(String(32), nullable=True)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "detection_id": (
                (self.detection_ids or [""])[0] if self.detection_ids else ""
            ),
            "detection_ids": list(self.detection_ids or []),
            "alert_fingerprint": self.alert_fingerprint,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "occurrence_count": self.occurrence_count,
            "host_id": self.host_id,
            "host_name": self.host_name,
            "user_id": self.user_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": list(self.evidence or []),
            "observables": list(self.observables or []),
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "acknowledged_at": (
                self.acknowledged_at.isoformat() if self.acknowledged_at else None
            ),
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "feedback": self.feedback,
        }


class AlertOccurrence(Base):
    """One merged detection occurrence (spec 3.33)."""

    __tablename__ = "alert_occurrences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    detection_id: Mapped[str] = mapped_column(String(64), index=True)
    event_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class AlertFeedback(Base):
    """Structured analyst feedback (spec 3.14, 3.34)."""

    __tablename__ = "alert_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    feedback_type: Mapped[str] = mapped_column(String(32), index=True)
    analyst_id: Mapped[str] = mapped_column(String(128), default="system")
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class AlertAuditEvent(Base):
    """Every state-changing operation (spec 3.27, 3.35)."""

    __tablename__ = "alert_audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(32), index=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    previous_status: Mapped[str] = mapped_column(String(16), default="")
    new_status: Mapped[str] = mapped_column(String(16), default="")
    actor: Mapped[str] = mapped_column(String(128), default="system")
    #: JSON payload for the action (spec 3.35 "metadata"). Named ``details``
    #: because ``metadata`` is a reserved declarative attribute name.
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )


class AlertSuppressionRule(Base):
    """Auditable, expiring suppression policy (spec 3.25, 3.26).

    A suppression must carry a documented reason, a defined scope and an
    expiration - permanent silent suppression is not allowed by default.
    """

    __tablename__ = "alert_suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    #: Scope matchers, e.g. {"detector_id": "D001", "host": "ml-host",
    #: "user": "*", "source_ip": "185.0.0.0/8"}. "*" matches anything.
    scope: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    suppressed_count: Mapped[int] = mapped_column(Integer, default=0)
