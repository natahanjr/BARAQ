"""v2 telemetry storage model (Phase 1).

The v2 ``EVENT`` is stored in its own table (``v2_events``), fully separate
from the v1 ``events`` table, so the new pipeline never shares state with
the frozen v1 detection engine.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.models import Base


class TelemetryEvent(Base):
    """One normalized v2 EVENT row (idempotent per fingerprint)."""

    __tablename__ = "v2_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    #: SHA-256 dedup key; unique, so replay is a no-op.
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    host: Mapped[str] = mapped_column(String(128), index=True, default="-")
    user: Mapped[str] = mapped_column(String(128), index=True, default="-")
    source: Mapped[str] = mapped_column(String(64), index=True, default="unknown")
    action: Mapped[str] = mapped_column(String(128), index=True, default="-")
    facts: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    org: Mapped[str] = mapped_column(String(64), default="", index=True)
    integrity: Mapped[str] = mapped_column(String(16), default="complete")
    #: Original raw record (audit / reprovenance); never queried, only kept.
    raw_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
