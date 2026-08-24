"""v2 detection storage model (Phase 2).

Dedicated ``detections`` table - the legacy v1 alert table is never reused
by the v2 detection engine. Fully separate from alerts/incidents/risk.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models import Base


class DetectionRecord(Base):
    """One v2 detection finding (Phase 2)."""

    __tablename__ = "detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: Deterministic id: DET-<detector>-<sha12>. Unique for the store.
    detection_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    detector_id: Mapped[str] = mapped_column(String(16), index=True)
    detector_version: Mapped[str] = mapped_column(String(16), default="1.0.0")

    title: Mapped[str] = mapped_column(String(256), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    severity: Mapped[str] = mapped_column(String(16), index=True, default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    event_id: Mapped[str] = mapped_column(String(128), default="")
    event_ids: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    host_id: Mapped[str] = mapped_column(String(128), default="")
    host_name: Mapped[str] = mapped_column(String(128), index=True, default="")
    user_id: Mapped[str] = mapped_column(String(128), default="")
    username: Mapped[str] = mapped_column(String(128), index=True, default="")
    source_ip: Mapped[str] = mapped_column(String(64), index=True, default="")
    destination_ip: Mapped[str] = mapped_column(String(64), default="")

    mitre_tactic: Mapped[str] = mapped_column(String(64), default="")
    mitre_technique: Mapped[str] = mapped_column(String(16), default="", index=True)

    evidence: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    observables: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    status: Mapped[str] = mapped_column(String(16), index=True, default="new")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "detection_id": self.detection_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_id": self.event_id,
            "event_ids": self.event_ids or [],
            "host_id": self.host_id,
            "host_name": self.host_name,
            "user_id": self.user_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": self.evidence or [],
            "observables": self.observables or [],
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }