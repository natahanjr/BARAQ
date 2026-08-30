"""Tests for SOAR automation playbooks (backend/automation/playbooks.py)."""

from __future__ import annotations

import pytest

from backend.automation.playbooks import (
    find_matching_playbooks,
    matches,
    run_playbook,
    validate_playbook,
)
from backend.database.models import (
    Alert,
    AutomationPlaybook,
    Incident,
    PlaybookRun,
)


def _mk_alert(
    db,
    rule: str = "brute_force",
    severity: str = "high",
    tactic: str = "Credential Access",
    risk_level: str = "HIGH",
    host: str = "WS-01",
    evidence: str = "User 'alice' from 192.168.1.50",
) -> Alert:
    alert = Alert(
        name=f"{rule} detection",
        description="test",
        severity=severity,
        status="open",
        confidence=0.8,
        score=6,
        risk_score=60.0,
        risk_level=risk_level,
        mitre_id="T1110",
        mitre_name="Brute Force",
        mitre_tactic=tactic,
        evidence=evidence,
        rule=rule,
        host=host,
        org="",
        event_count=1,
        detection_method="rule",
    )
    db.add(alert)
    db.flush()
    return alert


def _mk_playbook(db, name="auto_block", triggers=None, actions=None, enabled=True):
    playbook = AutomationPlaybook(
        name=name,
        description="test playbook",
        enabled=enabled,
        triggers=triggers or {"severity": ["high", "critical"]},
        actions=actions or [{"action": "block_ip"}, {"action": "notify"}],
    )
    db.add(playbook)
    db.flush()
    return playbook


def test_validate_playbook_ok():
    triggers, actions = validate_playbook(
        {"rules": ["brute_force"], "severity": "high", "min_risk_level": "medium"},
        ["block_ip", {"action": "quarantine"}],
    )
    assert triggers["severity"] == ["high"]
    assert triggers["min_risk_level"] == "MEDIUM"
    assert actions == [{"action": "block_ip"}, {"action": "quarantine"}]


def test_validate_playbook_rejects_unknown():
    with pytest.raises(ValueError):
        validate_playbook({"rules": ["x"], "bogus": 1}, ["block_ip"])
    with pytest.raises(ValueError):
        validate_playbook({}, ["nonsense_action"])
    with pytest.raises(ValueError):
        validate_playbook({}, [])
    with pytest.raises(ValueError):
        validate_playbook({"min_risk_level": "giga"}, ["block_ip"])


def test_matches_rules_and_severity(db):
    alert = _mk_alert(db, rule="brute_force", severity="high")
    assert matches(alert, {"rules": ["brute_force"], "severity": ["high"]})
    assert not matches(alert, {"rules": ["pass_the_hash"]})
    assert not matches(alert, {"severity": ["critical"]})
    assert matches(alert, {"rules": ["brute_force"], "severity": ["low", "high"]})


def test_matches_tactic_and_min_risk(db):
    alert = _mk_alert(db, tactic="Credential Access", risk_level="HIGH")
    assert matches(alert, {"tactics": ["Credential Access"]})
    assert not matches(alert, {"tactics": ["Lateral Movement"]})
    assert matches(alert, {"min_risk_level": "HIGH"})
    assert not matches(alert, {"min_risk_level": "CRITICAL"})


def test_run_playbook_logs_actions(db):
    alert = _mk_alert(db, host="WS-01", evidence="User 'alice' from 192.168.1.50")
    playbook = _mk_playbook(db, actions=[{"action": "block_ip"}])
    run = run_playbook(db, playbook, alert)
    db.commit()
    assert run.status == "completed"
    assert run.results[0]["action"] == "block_ip"
    assert run.results[0]["status"] == "success"
    assert "192.168.1.50" in run.results[0]["detail"]
    assert run.triggered_by == "auto"


def test_run_playbook_create_incident(db):
    alert = _mk_alert(db)
    playbook = _mk_playbook(
        db, name="open_case", actions=[{"action": "create_incident"}]
    )
    run_playbook(db, playbook, alert)
    db.commit()
    incident = db.query(Incident).filter_by(host="WS-01").first()
    assert incident is not None
    assert "Playbook incident" in incident.title
    # Second run against another alert reuses the open incident.
    alert2 = _mk_alert(db, rule="brute_force", host="WS-01")
    run_playbook(db, playbook, alert2)
    db.commit()
    assert (
        db.query(Incident).filter_by(title=f"Playbook incident: {alert.name}").count()
        == 1
    )


def test_run_playbook_partial_status(db):
    alert = _mk_alert(db, evidence="no ip here", host="")
    playbook = _mk_playbook(db, actions=[{"action": "notify"}, {"action": "block_ip"}])
    run = run_playbook(db, playbook, alert)
    assert run.status == "completed"  # block_ip without target is a success no-op
    assert run.results[0]["status"] == "success"


def test_find_matching_playbooks_respects_enabled(db):
    _mk_playbook(db, name="on", triggers={"severity": ["high"]}, enabled=True)
    _mk_playbook(db, name="off", triggers={"severity": ["high"]}, enabled=False)
    alert = _mk_alert(db, severity="high")
    names = [p.name for p in find_matching_playbooks(db, alert)]
    assert names == ["on"]


def test_playbook_api_crud(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    admin = {"X-API-Key": "baraq-dev-admin"}

    r = client.post(
        "/api/automation/playbooks",
        headers=admin,
        json={
            "name": "api_playbook",
            "description": "via api",
            "triggers": {"rules": ["brute_force"], "severity": ["high"]},
            "actions": [{"action": "block_ip"}, {"action": "notify"}],
        },
    )
    assert r.status_code == 200
    pid = r.json()["id"]

    r = client.get("/api/automation/playbooks", headers=admin)
    assert r.status_code == 200
    assert any(p["name"] == "api_playbook" for p in r.json()["playbooks"])

    r = client.patch(
        f"/api/automation/playbooks/{pid}",
        headers=admin,
        json={"enabled": False, "triggers": {"severity": ["critical"]}},
    )
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert r.json()["triggers"]["severity"] == ["critical"]

    # Non-admin cannot create.
    r = client.post(
        "/api/automation/playbooks",
        headers={"X-API-Key": "baraq-dev-analyst"},
        json={"name": "nope", "triggers": {}, "actions": ["notify"]},
    )
    assert r.status_code in (401, 403)

    # Invalid action rejected.
    r = client.post(
        "/api/automation/playbooks",
        headers=admin,
        json={"name": "bad", "triggers": {}, "actions": ["explode"]},
    )
    assert r.status_code == 400

    r = client.delete(f"/api/automation/playbooks/{pid}", headers=admin)
    assert r.status_code == 200

    # Every mutation above is audited (hash-chained log).
    r = client.get("/api/auth/audit", headers=admin, params={"limit": 50})
    assert r.status_code == 200
    actions = {row["action"] for row in r.json()["items"]}
    assert {"playbook.create", "playbook.update", "playbook.delete"} <= actions


def test_playbook_auto_fires_from_pipeline(db):
    """The detection pipeline fires matching playbooks for new alerts."""
    from backend.detection.alerting import AlertingService

    _mk_playbook(db, name="pipeline_block", triggers={"rules": ["brute_force"]})
    _mk_playbook(
        db,
        name="pipeline_other",
        triggers={"rules": ["usb_device"]},
    )

    findings = [
        {
            "rule": "brute_force",
            "name": "Brute force detected",
            "description": "x",
            "severity": "high",
            "confidence": 0.9,
            "evidence": "User 'bob' failed 12 logons from 10.0.0.9",
            "event_ids": [],
            "mitre_id": "T1110",
            "recommendation": "block",
        }
    ]
    # Reuse the real AlertManager shape: a lightweight adapter finding object.
    from types import SimpleNamespace

    f = SimpleNamespace(**findings[0])
    manager = AlertingService(db)
    created = manager.handle_findings([f], org="")
    assert len(created) == 1
    runs = db.query(PlaybookRun).all()
    assert len(runs) == 1
    assert runs[0].playbook_name == "pipeline_block"
    assert runs[0].alert_id == created[0].id
    assert runs[0].status == "completed"

    # The auto-fire is audited too (system actor).
    from backend.database.models import AuditLog

    entries = db.query(AuditLog).filter(AuditLog.action == "playbook.auto").all()
    assert len(entries) == 1
    assert entries[0].actor == "system"
    assert entries[0].entity_id == str(runs[0].playbook_id)
    assert "pipeline_block" in (entries[0].detail or "")
