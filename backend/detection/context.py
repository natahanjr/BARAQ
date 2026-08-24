"""Detection evaluation context (Phase 2).

Windowed detectors (brute force, ransomware behavior) need to look at
recent telemetry. The context is an *optional* read-only window over the
v2 event store. When no database is available (pure in-memory runs) the
context returns an empty window and windowed detectors deterministically
produce no detection.

The context reads ``v2_events`` only. It never writes, never touches v1
tables.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.telemetry.models import TelemetryEvent


class DetectionContext:
    """Read-only window provider over the v2 event store."""

    def __init__(self, db: Session | None = None):
        self._db = db

    def events_in_window(
        self,
        anchor: datetime,
        window_minutes: int,
        *,
        host: str | None = None,
        user: str | None = None,
        action: str | None = None,
        event_type: str | None = None,
        limit: int = 10_000,
    ) -> list[TelemetryEvent]:
        """Events with timestamp in [anchor - window, anchor], newest last.

        Deterministic ordering (timestamp, id). Empty when no DB is bound.
        """
        if self._db is None:
            return []
        since = anchor - timedelta(minutes=window_minutes)
        stmt = (
            select(TelemetryEvent)
            .where(TelemetryEvent.timestamp >= since, TelemetryEvent.timestamp <= anchor)
            .order_by(TelemetryEvent.timestamp, TelemetryEvent.id)
            .limit(limit)
        )
        if host is not None:
            stmt = stmt.where(TelemetryEvent.host == host)
        if user is not None:
            stmt = stmt.where(TelemetryEvent.user == user)
        if action is not None:
            stmt = stmt.where(TelemetryEvent.action == action)
        if event_type is not None:
            stmt = stmt.where(TelemetryEvent.event_type == event_type)
        return list(self._db.scalars(stmt).all())