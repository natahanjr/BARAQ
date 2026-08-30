"""Phase 3 alerting test helpers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from backend.alerting.models import (
    AlertAuditEvent,
    AlertFeedback,
    AlertOccurrence,
    AlertRecord,
    AlertSuppressionRule,
)
from backend.detection.contract import DETECTION, make_detection_id
from backend.detection.evidence import Evidence

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def dt(minutes_ago: float = 0.0) -> datetime:
    return T0 - timedelta(minutes=minutes_ago)


def detection(
    detector_id: str = "D001",
    host: str = "workstation-42",
    user: str = "alice",
    source_ip: str = "203.0.113.5",
    severity: str = "high",
    confidence: float = 0.91,
    minutes_ago: float = 0.0,
    mitre: str = "T1133",
    title: str = "",
    evidence: tuple[Evidence, ...] | None = None,
    **overrides,
) -> DETECTION:
    ts = dt(minutes_ago)
    if evidence is None:
        evidence = (
            Evidence("logon_type", 10, "Remote Interactive Logon"),
            Evidence("source_ip", source_ip, "Source classified as external"),
        )
    overrides.setdefault(
        "detection_id",
        make_detection_id(detector_id, host, user, source_ip, str(minutes_ago)),
    )
    return DETECTION(
        detector_id=detector_id,
        detector_version="1.0.0",
        event_id=f"evt-{detector_id}-{minutes_ago}-{host}-{user}",
        event_ids=(),
        timestamp=ts,
        first_seen=ts,
        last_seen=ts,
        event_type="authentication",
        host_name=host,
        username=user,
        source_ip=source_ip,
        title=title or f"{detector_id} detection",
        severity=severity,
        confidence=confidence,
        mitre_technique=mitre,
        mitre_tactic="Impact",
        evidence=evidence,
        **overrides,
    )


def stored_alerts(db) -> list[AlertRecord]:
    from sqlalchemy import select

    return list(db.scalars(select(AlertRecord).order_by(AlertRecord.id)).all())


def stored_occurrences(db) -> list[AlertOccurrence]:
    from sqlalchemy import select

    return list(db.scalars(select(AlertOccurrence).order_by(AlertOccurrence.id)).all())


def stored_audit(db) -> list[AlertAuditEvent]:
    from sqlalchemy import select

    return list(db.scalars(select(AlertAuditEvent).order_by(AlertAuditEvent.id)).all())


def stored_feedback(db) -> list[AlertFeedback]:
    from sqlalchemy import select

    return list(db.scalars(select(AlertFeedback).order_by(AlertFeedback.id)).all())


def stored_suppressions(db) -> list[AlertSuppressionRule]:
    from sqlalchemy import select

    return list(
        db.scalars(select(AlertSuppressionRule).order_by(AlertSuppressionRule.id)).all()
    )


def v1_counts(db) -> dict[str, int]:
    return {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in ("alerts", "incidents", "entity_risk")
    }
