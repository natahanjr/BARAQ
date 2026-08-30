"""Tests for the AI Security Assistant (chat, clear history, new intents)."""

from datetime import UTC, datetime, timedelta

from backend.ai.assistant import SecurityAssistant
from backend.database.models import Alert, AssistantMessage, Endpoint, NormalizedEvent


def _mk_alert(
    db,
    name="Brute Force - many failed logons",
    severity="high",
    rule="brute_force",
    mitre_id="T1110",
    tactic="Credential Access",
    status="open",
):
    a = Alert(
        name=name,
        description="many failed logons",
        severity=severity,
        status=status,
        confidence=0.9,
        mitre_id=mitre_id,
        mitre_name=name,
        mitre_tactic=tactic,
        rule=rule,
        evidence="4625 x 30 from 10.0.9.1",
        recommendation="Block the source IP.",
    )
    db.add(a)
    db.commit()
    return a


def test_chat_persists_turns_and_clear_history_removes_them(db):
    assistant = SecurityAssistant(db)
    reply = assistant.chat("hello")
    assert "Hello" in reply
    assert db.query(AssistantMessage).count() == 2

    cleared = assistant.clear_history()
    assert cleared == 2
    assert db.query(AssistantMessage).count() == 0


def test_chat_explain_alert_resolves_from_alert(db):
    a = _mk_alert(db)
    assistant = SecurityAssistant(db)
    reply = assistant.chat(f"explain alert {a.id}")
    assert f"Alert #{a.id}" in reply
    assert "Block the source IP" in reply


def test_multi_turn_followup_resolves_previous_alert(db):
    a = _mk_alert(db)
    assistant = SecurityAssistant(db)
    first = assistant.chat(f"explain alert {a.id}")
    assert a.name in first

    followup = assistant.chat("and how do I remediate that?")
    assert "Remediation plan" in followup
    assert a.name in followup


def test_alert_search_filters_by_severity(db):
    _mk_alert(db, name="Brute Force", severity="high", rule="brute_force")
    _mk_alert(db, name="USB device inserted", severity="low", rule="usb_device")
    assistant = SecurityAssistant(db)
    reply = assistant.chat("show open high severity alerts")
    assert "Brute Force" in reply
    assert "USB device" not in reply


def test_alert_search_keyword(db):
    _mk_alert(
        db,
        name="Suspicious PowerShell",
        severity="medium",
        rule="suspicious_powershell",
    )
    _mk_alert(db, name="RDP brute force", severity="high", rule="brute_force")
    assistant = SecurityAssistant(db)
    reply = assistant.chat("find alerts about powershell")
    assert "Suspicious PowerShell" in reply
    assert "RDP brute force" not in reply


def test_recent_events_filters_by_host(db):
    now = datetime.now(UTC)
    db.add(
        NormalizedEvent(
            event_id=4624,
            category="Authentication",
            user="alice",
            host="ws01",
            timestamp=now,
            message="logon",
            risk_score=10,
            severity="low",
            source="eventlog",
            raw_json={},
        )
    )
    db.add(
        NormalizedEvent(
            event_id=4688,
            category="Process",
            user="bob",
            host="ws02",
            timestamp=now,
            message="new process",
            risk_score=10,
            severity="low",
            source="eventlog",
            raw_json={},
        )
    )
    db.commit()
    assistant = SecurityAssistant(db)
    reply = assistant.chat("recent events from host ws01")
    assert "ws01" in reply
    assert "ws02" not in reply


def test_fleet_status_lists_endpoints(db):
    db.add(
        Endpoint(
            agent_id="agent-1",
            host="ws01",
            last_seen=datetime.now(UTC),
            events_total=120,
            alerts_total=1,
        )
    )
    db.add(
        Endpoint(
            agent_id="agent-2",
            host="stale-host",
            last_seen=datetime.now(UTC) - timedelta(hours=2),
        )
    )
    db.commit()
    assistant = SecurityAssistant(db)
    reply = assistant.chat("are my agents healthy")
    assert "Fleet status" in reply
    assert "ws01" in reply and "reporting" in reply
    assert "STALE" in reply


def test_ml_anomalies_lists_flagged_events(db):
    db.add(
        NormalizedEvent(
            event_id=4104,
            category="PowerShell",
            user="alice",
            host="ws01",
            timestamp=datetime.now(UTC),
            message="obfuscated script",
            risk_score=80,
            severity="high",
            source="eventlog",
            raw_json={},
            is_anomaly=True,
            ml_score=0.93,
        )
    )
    db.commit()
    assistant = SecurityAssistant(db)
    reply = assistant.chat("show ml anomalies")
    assert "ML-flagged" in reply
    assert "alice@ws01" in reply


def test_threat_intel_returns_verdict_or_graceful_reply(db):
    assistant = SecurityAssistant(db)
    reply = assistant.chat("is 203.0.113.9 malicious?")
    assert "203.0.113.9" in reply
    assert "Verdict" in reply or "No reputation data" in reply


def test_clear_history_endpoint(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    assistant = SecurityAssistant(db)
    assistant.chat("hello")
    assert db.query(AssistantMessage).count() == 2

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.delete("/api/assistant/history")
        assert r.status_code == 200
        assert r.json()["cleared"] == 2
    assert db.query(AssistantMessage).count() == 0
