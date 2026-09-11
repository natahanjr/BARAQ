"""Tests for backend.api.hunting router."""

import pytest
from datetime import UTC, datetime
from fastapi.testclient import TestClient

from backend.database.models import NormalizedEvent
from backend.main import app
from backend.search.engine import SearchError
from backend.security import API_KEY_HEADER

HEADERS = {API_KEY_HEADER: "baraq-dev-admin"}


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _seed_event(session, **overrides):
    defaults = dict(
        event_id=1001, category="Process", source="sysmon", user="admin",
        host="ws01", severity="info", risk="Low", message="process created",
        timestamp=datetime.now(UTC),
    )
    defaults.update(overrides)
    ev = NormalizedEvent(**defaults)
    session.add(ev)
    session.flush()
    return ev


def test_hunt_get_basic(client, db):
    _seed_event(db, source="sysmon")
    db.commit()
    resp = client.get("/api/hunting/search?q=source%3Dsysmon", headers=HEADERS)
    assert resp.status_code == 200
    data = resp.json()
    assert data["index"] == "events"
    assert data["total"] >= 1


def test_hunt_post_basic(client, db):
    _seed_event(db, source="sysmon", user="admin")
    db.commit()
    resp = client.post(
        "/api/hunting/search",
        json={"query": "source=sysmon user=admin"},
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


def test_hunt_invalid_query_returns_400(client):
    resp = client.post(
        "/api/hunting/search",
        json={"query": ""},
        headers=HEADERS,
    )
    assert resp.status_code == 400


def test_hunt_with_time_range(client, db):
    now = datetime.now(UTC)
    _seed_event(db, source="sysmon", timestamp=now)
    db.commit()
    resp = client.post(
        "/api/hunting/search",
        json={
            "query": "source=sysmon",
            "earliest": "-1h",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
