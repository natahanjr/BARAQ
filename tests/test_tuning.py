"""Tests for runtime detection tuning (backend/detection/tuning.py)."""

from __future__ import annotations

import pytest

from backend.detection.tuning import (
    get_tuning,
    rule_risk_weights,
    set_tuning,
    thresholds,
)
from backend.database.models import DetectionTuning


def test_default_tuning_matches_env(db):
    t = get_tuning(db)
    assert t["entity_risk_enabled"] is True
    assert t["risk_thresholds"]["medium"] > 0
    assert t["risk_thresholds"]["high"] > t["risk_thresholds"]["medium"]
    assert t["risk_thresholds"]["critical"] > t["risk_thresholds"]["high"]
    assert t["risk_decay_days"] > 0


def test_set_and_get_rule_risk_weights(db):
    set_tuning(db, "rule_risk_weights", {"brute_force": 2.5, "usb_device": 0.5})
    weights = rule_risk_weights(db)
    assert weights["brute_force"] == 2.5
    assert weights["usb_device"] == 0.5
    assert weights.get("lsass_dump", 1.0) == 1.0  # default


def test_set_thresholds_changes_levels(db):
    set_tuning(db, "risk_thresholds", {"medium": 10, "high": 20, "critical": 30})
    medium, high, critical = thresholds(db)
    assert (medium, high, critical) == (10.0, 20.0, 30.0)
    t = get_tuning(db)
    assert t["risk_thresholds"]["critical"] == 30.0


def test_unknown_key_rejected(db):
    with pytest.raises(ValueError):
        set_tuning(db, "nonsense_key", 1)


def test_bad_threshold_type_rejected(db):
    with pytest.raises(ValueError):
        set_tuning(db, "risk_thresholds", "medium")


def test_entity_risk_enabled_bool(db):
    set_tuning(db, "entity_risk_enabled", False)
    assert get_tuning(db)["entity_risk_enabled"] is False
    set_tuning(db, "entity_risk_enabled", "true")
    assert get_tuning(db)["entity_risk_enabled"] is True


def test_tuning_overrides_env_weights(db):
    set_tuning(db, "rule_risk_weights", {"brute_force": 4.0})
    # The manager folds DB tuning over env: brute_force now weighs 4x.
    from backend.database.models import Alert
    from backend.risk.entity_risk import EntityRisk, EntityRiskManager

    alert = Alert(
        name="bf",
        severity="high",
        status="open",
        confidence=0.8,
        score=0,
        risk_score=10.0,
        rule="brute_force",
        host="WS-1",
        org="",
        event_count=1,
        detection_method="rule",
    )
    db.add(alert)
    db.flush()
    manager = EntityRiskManager(db)
    manager.apply_alert(alert)
    entity = db.query(EntityRisk).filter_by(entity_kind="host", entity_name="WS-1").one()
    assert entity.score == 40.0  # 10 x 4.0 tuning weight


def test_tuning_thresholds_drive_escalation(db):
    from backend.database.models import Alert, EntityRisk
    from backend.risk.entity_risk import EntityRiskManager

    set_tuning(db, "risk_thresholds", {"medium": 5, "high": 10, "critical": 15})
    set_tuning(db, "risk_notable_window_hours", 6)
    alert = Alert(
        name="h",
        severity="medium",
        status="open",
        confidence=0.7,
        score=0,
        risk_score=12.0,
        rule="usb_device",
        host="WS-2",
        org="",
        event_count=1,
        detection_method="rule",
    )
    db.add(alert)
    db.flush()
    manager = EntityRiskManager(db)
    manager.apply_alert(alert)
    entity = db.query(EntityRisk).filter_by(entity_name="WS-2").one()
    assert entity.risk_level == "HIGH"  # 12 >= tuned high threshold of 10
    created = manager.escalate()
    assert len(created) == 1
    assert created[0].risk_level == "HIGH"


def test_tuning_disabled_stops_rba(db):
    from backend.database.models import Alert, EntityRisk
    from backend.risk.entity_risk import EntityRiskManager

    set_tuning(db, "entity_risk_enabled", False)
    alert = Alert(
        name="x",
        severity="low",
        status="open",
        confidence=0.5,
        score=0,
        risk_score=8.0,
        rule="usb_device",
        host="WS-3",
        org="",
        event_count=1,
        detection_method="rule",
    )
    db.add(alert)
    db.flush()
    manager = EntityRiskManager(db)
    touched = manager.apply_alert(alert)
    assert touched == []
    assert db.query(EntityRisk).count() == 0


def test_tuning_api_endpoints(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}

    r = client.get("/api/rba/tuning", headers=headers)
    assert r.status_code == 200
    assert "rule_risk_weights" in r.json()

    r = client.put(
        "/api/rba/tuning",
        headers=headers,
        json={"rule_risk_weights": {"brute_force": 3.0}, "risk_thresholds": {"high": 55}},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["rule_risk_weights"]["brute_force"] == 3.0
    assert body["risk_thresholds"]["high"] == 55.0

    # Analyst cannot tune.
    r = client.put(
        "/api/rba/tuning",
        headers={"X-API-Key": "baraq-dev-analyst"},
        json={"rule_risk_weights": {"brute_force": 9.0}},
    )
    assert r.status_code in (401, 403)

    # Invalid key rejected.
    r = client.put("/api/rba/tuning", headers=headers, json={"bogus": 1})
    assert r.status_code == 400