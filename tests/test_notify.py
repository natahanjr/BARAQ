"""Notification formatting + dispatch (webhook/Slack/Teams/Telegram)."""
import pytest

from backend import notify


def _alert(**over):
    base = {
        "id": 42,
        "severity": "critical",
        "risk_level": "Critical",
        "risk_score": 92.5,
        "name": "Malicious C2 beacon",
        "mitre_id": "T1071.001",
        "mitre_tactic": "Command and Control",
        "evidence": "Host connected to 198.51.100.9:443",
        "recommendation": "Isolate the host",
        "trigger_count": 3,
    }
    base.update(over)
    return base


def test_payload_shape():
    p = notify._payload(_alert())
    assert p["event"] == "alert.created"
    assert p["alert_id"] == 42
    assert p["severity"] == "critical"
    assert "evidence" in p


def test_severity_gating():
    assert notify._wanted("critical") is True
    assert notify._wanted("high") is True
    assert notify._wanted("medium") is False  # NOTIFY_MIN_SEVERITY defaults to high


def test_slack_payload():
    p = notify._slack_payload(_alert())
    assert "attachments" in p
    att = p["attachments"][0]
    assert att["color"] == "#e74c3c"
    assert att["mrkdwn_in"] == ["text"]
    assert "BARAQ alert #42" in att["title"]
    assert "*mitre_id:* T1071.001" in att["text"]


def test_teams_payload():
    p = notify._teams_payload(_alert())
    assert p["@type"] == "MessageCard"
    assert p["themeColor"] == "attention"
    assert any(f["name"] == "mitre_id" and f["value"] == "T1071.001" for f in p["sections"][0]["facts"])


def test_webhook_selects_slack_format(monkeypatch):
    captured = {}
    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = req.data.decode("utf-8")
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"
        return Resp()
    monkeypatch.setattr(notify, "WEBHOOK_URL", "https://hooks.slack.com/services/T0/B0/x")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    notify._send_webhook(_alert())
    assert "attachments" in captured["body"]
    assert captured["url"] == "https://hooks.slack.com/services/T0/B0/x"


def test_telegram_message(monkeypatch):
    captured = {}
    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["body"] = req.data.decode("utf-8")
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return b"ok"
        return Resp()
    monkeypatch.setattr(notify, "TELEGRAM_BOT_TOKEN", "111:AAA")
    monkeypatch.setattr(notify, "TELEGRAM_CHAT_ID", "-100123")
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    notify._send_telegram(_alert())
    assert "bot111:AAA" in captured["url"]
    import json as _json
    body = _json.loads(captured["body"])
    assert body["chat_id"] == "-100123"
    assert "Malicious C2 beacon" in body["text"]


def test_no_channels_noop(monkeypatch):
    monkeypatch.setattr(notify, "WEBHOOK_URL", "")
    monkeypatch.setattr(notify, "SMTP_HOST", "")
    monkeypatch.setattr(notify, "SMTP_TO", "")
    monkeypatch.setattr(notify, "TELEGRAM_BOT_TOKEN", "")
    monkeypatch.setattr(notify, "TELEGRAM_CHAT_ID", "")
    monkeypatch.setattr(notify, "TOAST_ENABLED", False)
    notify.notify_alert(_alert())  # must return without spawning anything