"""Phase 3 regression scenarios (spec 3.38, 3.50).

ALERT-001..ALERT-012 replay the exact noisy scenarios that caused the
original v1 alert flooding, through the v2 pipeline: detection -> alert
management -> analyst-facing alert.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from backend.alerting.engine import process_detection
from backend.alerting.models import AlertFeedback
from sqlalchemy import select

from tests.alerting.helpers import T0, detection, stored_alerts, stored_audit, v1_counts


def _scenario(db, detections, now=T0):
    alerts = []
    for d in detections:
        alert = process_detection(db, d, now=now)
        if alert is not None:
            alerts.append(alert)
    return alerts


def test_alert_001_single_valid_detection_one_alert(db):
    """Single valid detection -> one alert."""
    alerts = _scenario(db, [detection()])
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 1
    assert alerts[0].status == "OPEN"


def test_alert_002_repeated_same_detection_one_alert(db):
    """30 RDP detections -> ONE alert, 30 occurrences (spec 3.50)."""
    _scenario(db, [detection(minutes_ago=i * 0.2) for i in range(30)])
    alerts = stored_alerts(db)
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 30
    assert len(alerts[0].detection_ids) == 30
    assert alerts[0].severity == "high"
    assert alerts[0].confidence == 0.91


def test_alert_003_different_host_separate_alert(db):
    alerts = _scenario(db, [detection(host="host-a"), detection(host="host-b")])
    assert len(alerts) == 2


def test_alert_004_different_user_separate_alert(db):
    alerts = _scenario(db, [detection(user="alice"), detection(user="bob")])
    assert len(alerts) == 2


def test_alert_005_different_source_ip_separate_alert(db):
    alerts = _scenario(
        db,
        [detection(source_ip="185.0.0.1"), detection(source_ip="41.0.0.1")],
    )
    assert len(alerts) == 2


def test_alert_006_same_behavior_outside_window_new_alert(db):
    alerts = _scenario(
        db,
        [detection(minutes_ago=30), detection(minutes_ago=0.1)],
        now=T0 + timedelta(minutes=31),
    )
    assert len(alerts) == 2


def test_alert_007_resolved_alert_new_behavior_new_alert(db):
    alert = process_detection(db, detection(), now=T0)
    alert.status = "RESOLVED"
    alert.resolved_at = T0
    db.commit()
    alerts = _scenario(db, [detection(minutes_ago=0.1)], now=T0 + timedelta(minutes=1))
    assert len(alerts) == 1
    assert alerts[0].alert_id != alert.alert_id


def test_alert_008_suppressed_known_benign_no_visible_alert(db):
    from backend.alerting.suppression import create_rule

    create_rule(
        db,
        policy_id="SUP-RDP-ADMIN",
        reason="Approved administrative RDP source (maintenance window)",
        expires_at=T0 + timedelta(hours=6),
        scope={"detector_id": "D001", "source_ip": "185.0.0.0/8"},
    )
    db.commit()
    alerts = _scenario(db, [detection(source_ip="185.10.0.5")])
    assert alerts == []
    assert stored_alerts(db) == []


def test_alert_009_critical_detection_critical_alert(db):
    alert = process_detection(db, detection(severity="critical", confidence=0.99), now=T0)
    assert alert.severity == "critical"
    assert alert.status == "OPEN"


def test_alert_010_feedback_recorded(db):
    alert = process_detection(db, detection(), now=T0)
    from backend.alerting.feedback import submit

    submit(db, alert.alert_id, "FALSE_POSITIVE", analyst="analyst@example", comment="scan")
    db.commit()
    rows = db.scalars(select(AlertFeedback).where(AlertFeedback.alert_id == alert.alert_id)).all()
    assert len(rows) == 1
    assert rows[0].feedback_type == "FALSE_POSITIVE"
    assert rows[0].analyst_id == "analyst@example"


def test_alert_011_acknowledgement_audit_event(db):
    from backend.alerting import audit

    alert = process_detection(db, detection(), now=T0)
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = T0 + timedelta(minutes=1)
    alert.acknowledged_by = "analyst@example"
    audit.record(db, alert.alert_id, "ACKNOWLEDGED", "OPEN", "ACKNOWLEDGED",
                 actor="analyst@example")
    db.commit()
    events = stored_audit(db)
    assert [e.action for e in events] == ["CREATED", "ACKNOWLEDGED"]
    assert events[1].actor == "analyst@example"


def test_alert_012_illegal_state_transition_rejected(db):
    alert = process_detection(db, detection(), now=T0)
    alert.status = "CLOSED"
    db.commit()
    from backend.alerting.lifecycle import IllegalTransition, transition

    with pytest.raises(IllegalTransition):
        transition("CLOSED", "IN_PROGRESS")


def test_phase3_success_criteria_no_flood(db):
    """DoD: 18 brute-force detections -> 1 alert, 18 occurrences."""
    _scenario(
        db,
        [
            detection(
                detector_id="D002", mitre="T1110", severity="medium",
                confidence=0.65, minutes_ago=i * 0.3,
            )
            for i in range(18)
        ],
    )
    alerts = stored_alerts(db)
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 18


def test_phase3_isolation_incidents_risk_soar(db):
    """Spec 3.28-3.30, 3.40: alert ops never touch incidents/risk/SOAR."""
    before = v1_counts(db)
    alert = process_detection(db, detection(), now=T0)
    alert.status = "ACKNOWLEDGED"
    alert.acknowledged_at = T0
    alert.status = "RESOLVED"
    alert.resolved_at = T0 + timedelta(minutes=2)
    db.commit()
    assert v1_counts(db) == before