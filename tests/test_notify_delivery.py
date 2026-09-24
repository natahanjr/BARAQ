"""Notification delivery health: channel_health() shape + health API route.

No real email/webhook/toast is ever sent: these tests only read counters
(channel_health) or hit the GET route that wraps it.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_channel_health_shape():
    from backend import notify

    health = notify.channel_health()
    assert isinstance(health, dict)
    assert set(health) == {"channels", "fallback_dir", "retries"}
    assert isinstance(health["channels"], dict)
    assert isinstance(health["retries"], int)
    assert health["retries"] >= 1
    assert isinstance(health["fallback_dir"], str) and health["fallback_dir"]


def test_channel_health_per_channel_state(monkeypatch):
    """A recorded channel exposes the full counter payload."""
    from backend import notify

    fresh = notify.NotificationHealth()
    fresh.record("webhook", True)
    fresh.record("webhook", False, error="connection refused")
    monkeypatch.setattr(notify, "notification_health", fresh)

    channels = notify.channel_health()["channels"]
    assert set(channels) == {"webhook"}
    state = channels["webhook"]
    assert state["channel"] == "webhook"
    assert state["configured"] is True
    assert state["ok"] is False
    assert state["successes"] == 1
    assert state["failures"] == 1
    assert state["consecutive_failures"] == 1
    assert "connection refused" in state["last_error"]
    assert state["last_success_at"] and state["last_failure_at"]


def test_health_api_route(monkeypatch):
    """GET /api/system/notifications/health returns channel_health()."""
    from backend import notify
    from backend.main import app

    fresh = notify.NotificationHealth()
    fresh.record("email", True)
    monkeypatch.setattr(notify, "notification_health", fresh)

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/notifications/health")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"channels", "fallback_dir", "retries"}
    assert body["retries"] == notify.NOTIFY_RETRIES
    assert body["fallback_dir"] == notify.NOTIFY_FALLBACK_DIR
    assert set(body["channels"]) == {"email"}
    assert body["channels"]["email"]["successes"] == 1


def test_health_route_never_sends(monkeypatch):
    """The health route must not invoke any external sender."""
    from backend import notify
    from backend.main import app

    def boom(*_a, **_k):
        raise AssertionError("sender called during health check")

    for name in ("_send_webhook", "_send_email", "_send_telegram", "_send_toast"):
        monkeypatch.setattr(notify, name, boom)

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        assert client.get("/api/system/notifications/health").status_code == 200
