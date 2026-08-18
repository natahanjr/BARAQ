"""Alert engine tests (spec 3.2, 3.18-3.19, 3.28-3.31)."""
from __future__ import annotations

from datetime import timedelta

import pytest

from backend.alerting.engine import process_detection
from backend.detection.contract import make_detection_id

from tests.alerting.helpers import T0, detection, stored_alerts, v1_counts


def _d(**kw):
    kw.setdefault("detection_id", make_detection_id("D001", "e", "t"))
    return detection(**kw)


def test_single_valid_detection_creates_one_alert(db):
    alert = process_detection(db, _d(), now=T0)
    assert alert is not None
    assert alert.alert_id == "ALR-000001"
    assert alert.status == "OPEN"
    assert alert.occurrence_count == 1
    assert alert.severity == "high"
    assert alert.confidence == 0.91


def test_alert_id_sequential(db):
    process_detection(db, _d(), now=T0)
    process_detection(db, _d(host="other"), now=T0)
    ids = [a.alert_id for a in stored_alerts(db)]
    assert ids == ["ALR-000001", "ALR-000002"]


def test_ineligible_detection_creates_no_alert(db):
    result = process_detection(db, _d(detector_id="D003", severity="medium"), now=T0)
    assert result is None
    assert stored_alerts(db) == []


def test_severity_inherited_not_escalated(db):
    """Spec 3.18: no automatic HIGH+occurrences -> CRITICAL."""
    alert = process_detection(db, _d(), now=T0)
    for i in range(10):
        process_detection(db, _d(minutes_ago=0.1 + i * 0.01), now=T0)
    alert = stored_alerts(db)[0]
    assert alert.severity == "high"
    assert alert.occurrence_count == 11


def test_confidence_inherited_never_multiplied(db):
    """Spec 3.19: never confidence * occurrence_count."""
    alert = process_detection(db, _d(), now=T0)
    for i in range(5):
        process_detection(db, _d(minutes_ago=0.1 + i * 0.01), now=T0)
    alert = stored_alerts(db)[0]
    assert alert.confidence == 0.91


def test_evidence_preserved_on_alert(db):
    alert = process_detection(db, _d(), now=T0)
    evidence = alert.evidence
    assert evidence[0]["field"] == "logon_type"
    assert evidence[0]["value"] == 10
    assert "Remote Interactive Logon" in evidence[0]["reason"]


def test_mitre_mapping_preserved(db):
    alert = process_detection(db, _d(mitre="T1133"), now=T0)
    assert alert.mitre_technique == "T1133"


def test_detection_reference_retained(db):
    detection_ = _d()
    alert = process_detection(db, detection_, now=T0)
    assert detection_.detection_id in alert.detection_ids


def test_refuses_production_db_by_name(monkeypatch, db):
    import backend.config as config

    monkeypatch.setattr(
        config, "DATABASE_URL",
        "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel",
    )
    with pytest.raises(RuntimeError, match="production database"):
        process_detection(db, _d(), now=T0)


def test_engine_has_no_side_effects_on_v1_state(db):
    """Spec 3.28-3.30: alerts never touch incidents/risk/SOAR tables."""
    before = v1_counts(db)
    alert = process_detection(db, _d(), now=T0)
    process_detection(db, _d(minutes_ago=0.1), now=T0)
    assert alert is not None
    after = v1_counts(db)
    assert after == before


def test_alert_created_has_full_entity_context(db):
    alert = process_detection(
        db,
        _d(host="ml-host", user="ml-online-user", source_ip="185.0.0.1"),
        now=T0,
    )
    assert alert.host_name == "ml-host"
    assert alert.username == "ml-online-user"
    assert alert.source_ip == "185.0.0.1"
    assert alert.detector_id == "D001"
    assert alert.detector_version == "1.0.0"


def test_timestamp_is_detection_time_not_processing_time(db):
    alert = process_detection(db, _d(minutes_ago=3), now=T0)
    assert alert.first_seen == T0 - timedelta(minutes=3)
    assert alert.last_seen == T0 - timedelta(minutes=3)