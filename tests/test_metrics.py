"""Prometheus metrics endpoint tests."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "sentinel-dev-admin"}) as test_client:
        yield test_client


def test_authenticated_metrics_endpoint(client):
    resp = client.get("/api/system/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    body = resp.text
    assert "# HELP sentinel_events_total" in body
    assert "# TYPE sentinel_events_total counter" in body
    assert "sentinel_alerts_total{" in body
    assert "sentinel_uptime_seconds " in body
    assert "sentinel_collectors_enabled{collector=" in body


def test_public_metrics_endpoint_private_by_default(client):
    resp = client.get("/metrics")
    assert resp.status_code == 401


def test_metrics_accepts_bearer_api_key():
    """Prometheus v3 scrapes send the key as Authorization: Bearer."""
    from backend.main import app

    with TestClient(app) as bare:
        ok = bare.get(
            "/api/system/metrics",
            headers={"Authorization": "Bearer sentinel-dev-admin"},
        )
        assert ok.status_code == 200
        assert "sentinel_events_total" in ok.text
        bad = bare.get(
            "/api/system/metrics",
            headers={"Authorization": "Bearer not-a-real-key"},
        )
        assert bad.status_code == 401


def test_metric_parseability(client):
    body = client.get("/api/system/metrics").text
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        assert " " in line, f"malformed metric line: {line!r}"
