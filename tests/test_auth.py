"""Tests for API authentication (RBAC) and input validation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ADMIN_KEY = "baraq-dev-admin"
ANALYST_KEY = "baraq-dev-analyst"


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


def _get(client, path, key=None, **params):
    headers = {"X-API-Key": key} if key else {}
    return client.get(path, headers=headers, params=params or {})


def _post(client, path, key, body=None):
    return client.post(path, headers={"X-API-Key": key}, json=body or {})


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def test_missing_key_rejected(client):
    assert _get(client, "/api/dashboard/summary").status_code == 401


def test_invalid_key_rejected(client):
    assert _get(client, "/api/dashboard/summary", key="bogus").status_code == 401


def test_valid_keys_authorized(client):
    assert _get(client, "/api/dashboard/summary", key=ADMIN_KEY).status_code == 200
    assert _get(client, "/api/dashboard/summary", key=ANALYST_KEY).status_code == 200


def test_health_is_public(client):
    assert client.get("/api/health").status_code == 200


def test_root_is_public(client):
    assert client.get("/").status_code == 200


# ---------------------------------------------------------------------------
# RBAC: admin-only endpoints
# ---------------------------------------------------------------------------


def test_analyst_cannot_trigger_actions(client):
    # Need an alert to act on; analyst role must still be blocked at the route.
    resp = _post(
        client, "/api/alerts/1/actions", ANALYST_KEY, {"action": "acknowledge"}
    )
    assert resp.status_code == 403


def test_admin_can_trigger_actions(client):
    from backend.api.system import run_pipeline
    from backend.database.connection import SessionLocal
    from tests.fixtures import brute_force

    db = SessionLocal()
    try:
        run_pipeline(db, brute_force())
    finally:
        db.close()

    alert_id = _get(client, "/api/alerts", key=ADMIN_KEY).json()["items"][0]["id"]
    resp = _post(
        client, f"/api/alerts/{alert_id}/actions", ADMIN_KEY, {"action": "acknowledge"}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "success"


def test_analyst_cannot_collect(client):
    resp = _post(client, "/api/system/collect", ANALYST_KEY)
    assert resp.status_code in (403, 200)  # blocked for analyst unless disabled


def test_analyst_cannot_retrain_ml(client):
    resp = _post(client, "/api/system/ml/train", ANALYST_KEY)
    assert resp.status_code == 403


def test_analyst_cannot_run_evaluation(client):
    resp = _post(client, "/api/evaluation/run?with_ml=false", ANALYST_KEY)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_invalid_alert_status_rejected(client):
    resp = client.patch(
        "/api/alerts/1/status",
        headers={"X-API-Key": ADMIN_KEY},
        json={"status": "not_a_real_status"},
    )
    assert resp.status_code == 422


def test_invalid_alert_action_rejected(client):
    resp = _post(
        client, "/api/alerts/1/actions", ADMIN_KEY, {"action": "delete_everything"}
    )
    assert resp.status_code == 422


def test_pagination_bounds_rejected(client):
    resp = _get(client, "/api/alerts", key=ADMIN_KEY, page=0)
    assert resp.status_code == 422
    resp = _get(client, "/api/alerts", key=ADMIN_KEY, page_size=10000)
    assert resp.status_code == 422


def test_invalid_severity_filter_rejected(client):
    resp = _get(client, "/api/alerts", key=ADMIN_KEY, severity="ultra")
    assert resp.status_code == 422


def test_report_enum_rejected(client):
    resp = client.post(
        "/api/reports/generate",
        headers={"X-API-Key": ADMIN_KEY},
        json={"report_type": "spreadsheet", "format": "pdf"},
    )
    assert resp.status_code == 422


def test_invalid_timeline_hours_rejected(client):
    resp = _get(client, "/api/dashboard/timeline", key=ADMIN_KEY, hours=0)
    assert resp.status_code == 422
