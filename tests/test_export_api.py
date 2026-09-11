"""Tests for backend.api.export router."""

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.database.connection import SessionLocal
from backend.database.models import Alert, NormalizedEvent
from backend.main import app
from backend.security import API_KEY_HEADER

HEADERS = {API_KEY_HEADER: "baraq-dev-admin"}


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _seed_event(session, **overrides):
    from datetime import UTC, datetime
    defaults = dict(
        event_id=1, category="Process", source="sysmon", user="admin",
        host="ws01", severity="info", risk="Low", message="test event",
        timestamp=datetime.now(UTC),
    )
    defaults.update(overrides)
    ev = NormalizedEvent(**defaults)
    session.add(ev)
    session.flush()
    return ev


def _seed_alert(session, **overrides):
    defaults = dict(
        name="TestAlert", severity="medium", status="open", confidence=0.8,
        score=50.0, mitre_id="T1059", mitre_tactic="Execution",
        host="ws01", evidence="suspicious powershell",
    )
    defaults.update(overrides)
    al = Alert(**defaults)
    session.add(al)
    session.flush()
    return al


def test_list_export_types(client):
    resp = client.get("/api/export/types", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["types"]) == 15


def test_export_unknown_type_returns_404(client):
    resp = client.get("/api/export/nonexistent", headers=HEADERS)
    assert resp.status_code == 404


def test_export_events_csv(client, db):
    _seed_event(db)
    db.commit()
    resp = client.get("/api/export/events?format=csv", headers=HEADERS)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    body = resp.text
    assert "event_id" in body


def test_export_events_json(client, db):
    _seed_event(db)
    db.commit()
    resp = client.get("/api/export/events?format=json", headers=HEADERS)
    assert resp.status_code == 200
    assert "application/json" in resp.headers["content-type"]
    payload = resp.json()
    assert payload["export_type"] == "events"
    assert payload["returned"] >= 1


def test_export_alerts_csv(client, db):
    _seed_alert(db)
    db.commit()
    resp = client.get("/api/export/alerts?format=csv", headers=HEADERS)
    assert resp.status_code == 200
    body = resp.text
    assert "TestAlert" in body


def test_export_with_severity_filter(client, db):
    _seed_alert(db, name="HighAlert", severity="high")
    _seed_alert(db, name="LowAlert", severity="low")
    db.commit()
    resp = client.get("/api/export/alerts?severity=high&format=json", headers=HEADERS)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["returned"] == 1


def test_export_with_search(client, db):
    _seed_alert(db, name="BruteForce", evidence="brute force login attempts")
    _seed_alert(db, name="PortScan", evidence="port scan detected")
    db.commit()
    resp = client.get("/api/export/alerts?search=brute&format=json", headers=HEADERS)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["returned"] == 1


def test_export_with_pagination(client, db):
    for i in range(5):
        _seed_alert(db, name=f"Alert{i}")
    db.commit()
    resp = client.get("/api/export/alerts?limit=2&offset=0&format=json", headers=HEADERS)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["returned"] == 2
    assert payload["total"] == 5
