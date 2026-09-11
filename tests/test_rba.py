"""Tests for backend.detection.rba.RBAManager."""

import pytest
from sqlalchemy import select

from backend.database.models import Alert, Incident
from backend.detection.rba import RBAManager


def _make_alert(session, *, name="TestAlert", host="host1", org="", severity="medium",
                rule="", demo=False, risk_score=50.0, mitre_tactic="TA0001",
                evidence="", status="open"):
    alert = Alert(
        name=name, host=host, org=org, severity=severity, rule=rule,
        demo=demo, risk_score=risk_score, mitre_tactic=mitre_tactic,
        evidence=evidence, status=status, mitre_id="T1000",
    )
    session.add(alert)
    session.flush()
    return alert


# ── _is_noise ───────────────────────────────────────────────────────────────


def test_is_noise_demo_alert(db):
    alert = _make_alert(db, demo=True)
    assert RBAManager._is_noise(alert) is True


def test_is_noise_entity_risk(db):
    alert = _make_alert(db, rule="entity_risk")
    assert RBAManager._is_noise(alert) is True


def test_is_noise_developer_workflow(db):
    alert = _make_alert(db, evidence="strong developer-workflow context detected")
    assert RBAManager._is_noise(alert) is True


def test_is_not_noise_normal_alert(db):
    alert = _make_alert(db, evidence="brute force pattern detected")
    assert RBAManager._is_noise(alert) is False


# ── _get_level ──────────────────────────────────────────────────────────────


def test_get_level_critical(db):
    mgr = RBAManager(db)
    assert mgr._get_level(85) == "CRITICAL"
    assert mgr._get_level(100) == "CRITICAL"


def test_get_level_high(db):
    mgr = RBAManager(db)
    assert mgr._get_level(65) == "HIGH"
    assert mgr._get_level(84) == "HIGH"


def test_get_level_medium(db):
    mgr = RBAManager(db)
    assert mgr._get_level(40) == "MEDIUM"
    assert mgr._get_level(64) == "MEDIUM"


def test_get_level_low(db):
    mgr = RBAManager(db)
    assert mgr._get_level(39) == "LOW"
    assert mgr._get_level(0) == "LOW"


# ── evaluate_entity_risk ───────────────────────────────────────────────────


def test_evaluate_no_alerts_returns_none(db):
    mgr = RBAManager(db, risk_threshold=50.0)
    result = mgr.evaluate_entity_risk("empty-host")
    assert result is None


def test_evaluate_below_min_alerts_returns_none(db):
    _make_alert(db, host="h1", risk_score=60.0, severity="high", mitre_tactic="TA0001")
    mgr = RBAManager(db, risk_threshold=50.0)
    result = mgr.evaluate_entity_risk("h1")
    assert result is None


def test_evaluate_below_risk_threshold_returns_none(db):
    _make_alert(db, host="h2", risk_score=25.0, severity="low",
                mitre_tactic="TA0001", evidence="brute force")
    _make_alert(db, host="h2", risk_score=25.0, severity="low",
                mitre_tactic="TA0002", evidence="password spray")
    mgr = RBAManager(db, risk_threshold=50.0)
    result = mgr.evaluate_entity_risk("h2")
    assert result is None


def test_evaluate_creates_incident_above_threshold(db):
    _make_alert(db, host="h3", risk_score=40.0, severity="high",
                mitre_tactic="TA0001", evidence="lateral movement")
    _make_alert(db, host="h3", risk_score=40.0, severity="high",
                mitre_tactic="TA0002", evidence="credential access")
    mgr = RBAManager(db, risk_threshold=50.0)
    result = mgr.evaluate_entity_risk("h3")
    assert result is not None
    assert result.risk_score >= 50.0
    assert result.host == "h3"
    assert result.status == "open"


def test_evaluate_no_duplicate_incidents(db):
    _make_alert(db, host="h4", risk_score=40.0, severity="high",
                mitre_tactic="TA0001", evidence="lateral movement")
    _make_alert(db, host="h4", risk_score=40.0, severity="high",
                mitre_tactic="TA0002", evidence="credential access")
    mgr = RBAManager(db, risk_threshold=50.0)
    first = mgr.evaluate_entity_risk("h4")
    second = mgr.evaluate_entity_risk("h4")
    assert first is not None
    assert second is not None
    assert first.id == second.id
    incidents = db.scalars(select(Incident).where(Incident.host == "h4")).all()
    assert len(incidents) == 1
