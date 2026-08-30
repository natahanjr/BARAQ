"""Tests for the automated data-retention purge."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.database.models import (
    Alert,
    AlertEventLink,
    DashboardSnapshot,
    NormalizedEvent,
    ThreatIntelRecord,
)
from backend.database.retention import purge_old_data


def _event_ts(days_ago: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days_ago)


def test_purge_removes_old_events_and_keeps_fresh(db):
    db.add(
        NormalizedEvent(
            event_id=4624,
            category="authentication",
            user="old",
            host="HOST",
            risk_score=10,
            timestamp=_event_ts(45),
        )
    )
    db.add(
        NormalizedEvent(
            event_id=4624,
            category="authentication",
            user="new",
            host="HOST",
            risk_score=10,
            timestamp=_event_ts(1),
        )
    )
    db.commit()

    purged = purge_old_data(db, days=30)

    assert purged["events"] == 1
    remaining = db.query(NormalizedEvent).all()
    assert len(remaining) == 1
    assert remaining[0].user == "new"


def test_purge_removes_old_alerts_and_snapshots(db):
    db.add(
        Alert(
            name="Old alert",
            severity="high",
            status="open",
            mitre_id="T1110",
            mitre_name="Brute Force",
            mitre_tactic="Credential Access",
            risk_score=80,
            risk_level="HIGH",
            created_at=_event_ts(45),
        )
    )
    db.add(
        DashboardSnapshot(
            security_score=90,
            total_events=10,
            active_alerts=0,
            critical_threats=0,
            events_last_hour=1,
            timestamp=_event_ts(45),
        )
    )
    db.commit()

    purged = purge_old_data(db, days=30)

    assert purged["alerts"] == 1
    assert purged["dashboard_snapshots"] == 1
    assert db.query(Alert).count() == 0
    assert db.query(DashboardSnapshot).count() == 0


def test_purge_keeps_recent_alerts(db):
    db.add(
        Alert(
            name="Fresh alert",
            severity="high",
            status="open",
            mitre_id="T1110",
            mitre_name="Brute Force",
            mitre_tactic="Credential Access",
            risk_score=80,
            risk_level="HIGH",
            created_at=_event_ts(2),
        )
    )
    db.commit()

    purged = purge_old_data(db, days=30)

    assert purged["alerts"] == 0
    assert db.query(Alert).count() == 1


def test_purge_cascades_alert_links(db):
    event = NormalizedEvent(
        event_id=4625,
        category="authentication",
        user="attacker",
        host="HOST",
        risk_score=10,
        timestamp=_event_ts(45),
    )
    db.add(event)
    db.flush()
    alert = Alert(
        name="Old alert",
        severity="high",
        status="open",
        mitre_id="T1110",
        mitre_name="Brute Force",
        mitre_tactic="Credential Access",
        risk_score=80,
        risk_level="HIGH",
        created_at=_event_ts(45),
    )
    db.add(alert)
    db.flush()
    db.execute(
        AlertEventLink.__table__.insert().values(alert_id=alert.id, event_id=event.id)
    )
    db.commit()

    purge_old_data(db, days=30)

    assert db.query(NormalizedEvent).count() == 0
    assert db.query(Alert).count() == 0


def test_purge_removes_stale_threat_intel_cache(db):
    db.add(
        ThreatIntelRecord(
            indicator="8.8.8.8",
            kind="ip",
            category="malicious",
            label="baseline",
            confidence=0.9,
            sources=["embedded-ioc"],
            checked_at=_event_ts(45),
        )
    )
    db.add(
        ThreatIntelRecord(
            indicator="1.1.1.1",
            kind="ip",
            category="benign",
            checked_at=_event_ts(1),
        )
    )
    db.commit()

    purged = purge_old_data(db, days=30)

    assert purged["threat_intel_records"] == 1
    remaining = db.query(ThreatIntelRecord).all()
    assert len(remaining) == 1
    assert remaining[0].indicator == "1.1.1.1"


def test_purge_keeps_fresh_intel(db):
    db.add(
        ThreatIntelRecord(
            indicator="9.9.9.9",
            kind="ip",
            category="suspicious",
            checked_at=_event_ts(2),
        )
    )
    db.commit()

    purged = purge_old_data(db, days=30)

    assert purged["threat_intel_records"] == 0
    assert db.query(ThreatIntelRecord).count() == 1
