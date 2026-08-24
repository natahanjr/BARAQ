"""Test the multi-endpoint ingest API and fleet status."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


def test_ingest_requires_agent_key(client):
    resp = client.post("/api/ingest", json={"records": [{"event_id": 1}]})
    assert resp.status_code == 401
    assert "agent key" in resp.json()["detail"].lower()


def test_ingest_rejects_unknown_agent_key(client):
    resp = client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-nope"},
        json={"records": [{"event_id": 1}]},
    )
    assert resp.status_code == 401


def test_ingest_attributes_host_and_creates_endpoint(client):
    from tests.fixtures import brute_force

    resp = client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={"records": brute_force(attempts=6)},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "agent-dev"
    assert data["host"] == "agent-dev"
    assert data["saved_events"] >= 6
    assert data["alerts_created"] >= 1

    fleet = client.get("/api/endpoints").json()["items"]
    ep = next(e for e in fleet if e["agent_id"] == "agent-dev")
    assert ep["host"] == "agent-dev"
    assert ep["records_total"] >= 6
    assert ep["events_total"] >= 6
    assert ep["alerts_total"] >= 1
    assert ep["last_seen"]


def test_ingest_host_override_tags_alerts(client):
    resp = client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={
            "records": [
                {
                    "event_id": 1,
                    "source": "test",
                    "timestamp": "2026-08-01T12:00:00Z",
                }
            ],
            "host": "corp-laptop-42",
        },
    )
    assert resp.status_code == 200

    alerts = client.get("/api/alerts", params={"page_size": 10}).json()["items"]
    if alerts:
        assert all(a["host"] == "corp-laptop-42" for a in alerts if a["host"])

    ep = next(
        e for e in client.get("/api/endpoints").json()["items"] if e["agent_id"] == "agent-dev"
    )
    assert ep["host"] == "corp-laptop-42"


def test_agent_pipeline_events_carry_host(client):
    from backend.database.connection import SessionLocal
    from backend.database.models import NormalizedEvent

    client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={
            "records": [
                {
                    "event_id": 1,
                    "source": "test",
                    "message": "x",
                    "timestamp": "2026-08-01T12:00:00Z",
                }
            ]
        },
    )
    db = SessionLocal()
    try:
        hosts = {e.host for e in db.query(NormalizedEvent).limit(50)}
    finally:
        db.close()
    assert "agent-dev" in hosts


def test_list_endpoints_requires_auth():
    from backend.main import app

    with TestClient(app) as bare:
        assert bare.get("/api/endpoints").status_code == 401
