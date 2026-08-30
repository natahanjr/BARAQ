"""Ticketing integrations (roadmap 6.3): Jira, ServiceNow, SDK."""

from __future__ import annotations

import backend.integrations.client as client_mod
from backend.database.models import Alert


def _mk_alert(db, severity="high", name="Beacon out") -> Alert:
    row = Alert(
        name=name,
        description="test",
        severity=severity,
        confidence=0.9,
        score=70,
        mitre_id="T1071",
        mitre_name="App Layer Protocol",
        evidence="http://evil.example/x",
        rule="test-rule",
        host="host1",
        risk_score=70,
        risk_level="HIGH",
    )
    db.add(row)
    db.commit()
    return row


def test_below_min_severity_not_dispatched(db):
    alert = _mk_alert(db, severity="low")
    result = client_mod.dispatch_alert(db, alert)
    assert result["dispatched"] is False
    assert result["reason"] == "below min severity"


def test_no_integrations_configured(db):
    alert = _mk_alert(db)
    result = client_mod.dispatch_alert(db, alert)
    assert result["dispatched"] is False


def test_jira_and_snow_dispatch(db, monkeypatch):
    captured: list[dict] = []

    def fake_post(url, headers, payload):
        captured.append({"url": url, "headers": headers, "payload": payload})
        if "jira" in url:
            return {"key": "SOC-42"}
        return {"result": {"sys_id": "abc123"}}

    monkeypatch.setattr(client_mod, "_post_json", fake_post)
    monkeypatch.setattr(client_mod, "JIRA_URL", "https://jira.corp")
    monkeypatch.setattr(client_mod, "JIRA_API_TOKEN", "pat")
    monkeypatch.setattr(client_mod, "JIRA_PROJECT_KEY", "SOC")
    monkeypatch.setattr(client_mod, "JIRA_ISSUE_TYPE", "Task")
    monkeypatch.setattr(client_mod, "JIRA_EMAIL", "")
    monkeypatch.setattr(client_mod, "SERVICENOW_INSTANCE", "acme")
    monkeypatch.setattr(client_mod, "SERVICENOW_USERNAME", "svc")
    monkeypatch.setattr(client_mod, "SERVICENOW_PASSWORD", "pw")
    monkeypatch.setattr(client_mod, "SERVICENOW_TABLE", "incident")

    alert = _mk_alert(db)
    result = client_mod.dispatch_alert(db, alert)

    assert result["dispatched"] is True
    keys = {r["key"] for r in result["results"]}
    assert keys == {"SOC-42", "abc123"}
    assert len(captured) == 2
    assert alert.ticket_links is not None and len(alert.ticket_links) == 2

    jira = captured[0]
    assert jira["url"] == "https://jira.corp/rest/api/2/issue"
    assert "Bearer pat" in jira["headers"]["Authorization"]
    assert jira["payload"]["fields"]["project"]["key"] == "SOC"

    snow = captured[1]
    assert "acme.service-now.com" in snow["url"]
    assert snow["payload"]["severity"] == 2


def test_health_tracked_on_failure(db, monkeypatch):
    monkeypatch.setattr(client_mod, "_post_json", lambda *a, **k: None)
    monkeypatch.setattr(client_mod, "JIRA_URL", "https://jira.corp")
    monkeypatch.setattr(client_mod, "JIRA_API_TOKEN", "pat")
    monkeypatch.setattr(client_mod, "JIRA_PROJECT_KEY", "SOC")
    monkeypatch.setattr(client_mod, "JIRA_ISSUE_TYPE", "Task")
    monkeypatch.setattr(client_mod, "JIRA_EMAIL", "")

    alert = _mk_alert(db)
    client_mod.integration_health._state.clear()
    result = client_mod.dispatch_alert(db, alert)
    assert result["dispatched"] is False
    status = client_mod.integration_status()
    assert "jira" in status["configured"]
    assert status["channels"]["jira"]["ok"] is False
    assert status["channels"]["jira"]["failures"] == 1


def test_dispatch_api_endpoint(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    alert = _mk_alert(db)
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/integrations/status")
        assert r.status_code == 200
        assert "configured" in r.json()

        r = client.post(f"/api/integrations/dispatch/{alert.id}")
        assert r.status_code == 200
        assert r.json()["alert_id"] == alert.id
        assert r.json()["dispatched"] is False  # nothing configured in tests

        r = client.post("/api/integrations/dispatch/999999")
        assert r.status_code == 404

    with TestClient(app, headers={"X-API-Key": "baraq-dev-analyst"}) as client:
        r = client.post(f"/api/integrations/dispatch/{alert.id}")
        assert r.status_code == 403


def test_sdk_client_basic_flow(monkeypatch):
    from backend.integrations.sdk import BARAQClient

    calls: list[tuple] = []

    class FakeResp:
        def __init__(self, payload):
            self._payload = payload

        def read(self):
            import json

            return json.dumps(self._payload).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None, context=None):
        calls.append((req.method, req.full_url, req.get_header("X-api-key")))
        if "alerts" in req.full_url and req.method == "GET":
            return FakeResp({"items": [{"id": 1, "name": "x"}], "total": 1})
        if req.method == "POST" and "incidents" in req.full_url:
            return FakeResp({"id": 7, "title": "Ransomware"})
        return FakeResp({})

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = BARAQClient("https://soc.corp:8443", api_key="k1")
    assert client.alerts(status="open")["items"][0]["id"] == 1
    assert client.alerts(status="open", limit=5, org="")["total"] == 1
    created = client.incident_create("Ransomware", alert_ids=[1])
    assert created["id"] == 7

    methods = {c[0] for c in calls}
    assert "GET" in methods and "POST" in methods
    auth = next(c[2] for c in calls)
    assert auth == "k1"


def test_sdk_client_http_error(monkeypatch):
    import io
    import urllib.error
    import urllib.request

    from backend.integrations.sdk import BARAQClient, BARAQError

    def boom(req, timeout=None, context=None):
        resp = io.BytesIO(b'{"detail": "nope"}')
        raise urllib.error.HTTPError(
            "https://soc.corp/1", 500, "Internal Server Error", {}, resp
        )

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    client = BARAQClient("https://soc.corp:8443", api_key="k1", verify_ssl=False)
    try:
        client.alerts()
        raise AssertionError("expected BARAQError")
    except BARAQError as exc:
        assert exc.status == 500
        assert exc.detail == {"detail": "nope"}
