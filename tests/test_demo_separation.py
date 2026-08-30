"""Demo/test telemetry separation (analyst P0: seeded demo data must never
pollute production views).

Every production-facing endpoint excludes demo rows by default; include_demo=1
opts back in. Search excludes demo unless include_demo or an explicit
demo=true filter is given.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    EntityRisk,
    Incident,
    NormalizedEvent,
    SavedSearch,
)


@pytest.fixture()
def client(db):
    from backend.main import app

    app.dependency_overrides[get_db] = lambda: db
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _mk_event(db, demo: bool, user="prod", host="WS-PROD", event_id=4625):
    e = NormalizedEvent(
        event_id=event_id,
        category="Logon Failure",
        source="windows",
        user=user,
        host=host,
        risk="Medium",
        severity="medium",
        message=f"Logon failure for {user}",
        timestamp=datetime.now(UTC) - timedelta(minutes=5),
        raw_json={"facts": {}},
        demo=demo,
    )
    db.add(e)
    db.flush()
    return e


def _mk_alert(db, demo: bool, user="prod", host="WS-PROD", rule="brute_force"):
    a = Alert(
        rule=rule,
        name=f"Brute force on {user}",
        severity="high",
        confidence=0.9,
        status="open",
        mitre_id="T1110",
        mitre_tactic="Credential Access",
        mitre_name="Brute Force",
        evidence=f"User '{user}' from 10.0.0.9",
        event_count=1,
        risk_score=60.0,
        risk_level="HIGH",
        org="",
        demo=demo,
    )
    db.add(a)
    db.flush()
    return a


def _mk_incident(db, demo: bool, title="Severity incident"):
    i = Incident(
        title=title,
        severity="high",
        status="open",
        description="demo separation",
        org="",
        demo=demo,
    )
    db.add(i)
    db.flush()
    return i


def _mk_risk(db, demo: bool, name="prod-user"):
    r = EntityRisk(
        entity_kind="user",
        entity_name=name,
        risk_level="HIGH",
        score=66.0,
        alerts_count=1,
        last_escalated_level="",
        last_escalated_score=0.0,
        demo=demo,
    )
    db.add(r)
    db.flush()
    return r


@pytest.fixture()
def seeded(db, client):
    """One production alert/event/entity/incident plus one demo twin."""
    _mk_event(db, demo=False, user="prod-user")
    _mk_event(db, demo=True, user="demo-user")
    _mk_alert(db, demo=False, user="prod-user")
    _mk_alert(db, demo=True, user="demo-user")
    _mk_incident(db, demo=False)
    _mk_incident(db, demo=True)
    _mk_risk(db, demo=False, name="prod-user")
    _mk_risk(db, demo=True, name="demo-user")
    db.commit()


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------
def test_alerts_exclude_demo_by_default(seeded, client, db):
    items = client.get("/api/alerts", params={"page_size": 50}).json()["items"]
    assert all(i["demo"] is False for i in items)
    assert all("demo-user" not in i["evidence"] for i in items)


def test_alerts_include_demo_on_demand(seeded, client):
    items = client.get(
        "/api/alerts", params={"page_size": 50, "include_demo": 1}
    ).json()["items"]
    assert any(i["demo"] for i in items)
    assert any("demo-user" in i["evidence"] for i in items)
    assert any("prod-user" in i["evidence"] for i in items)


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------
def test_events_exclude_demo_by_default(seeded, client):
    items = client.get("/api/events", params={"page_size": 50}).json()["items"]
    assert {i["user"] for i in items} == {"prod-user"}
    assert all(i["demo"] is False for i in items)


def test_events_include_demo_on_demand(seeded, client):
    items = client.get(
        "/api/events", params={"page_size": 50, "include_demo": 1}
    ).json()["items"]
    assert {i["user"] for i in items} == {"prod-user", "demo-user"}


# ---------------------------------------------------------------------------
# incidents
# ---------------------------------------------------------------------------
def test_incidents_exclude_demo_by_default(seeded, client):
    data = client.get("/api/incidents", params={"limit": 50}).json()
    assert all(i["demo"] is False for i in data["items"])


def test_incidents_include_demo_on_demand(seeded, client):
    data = client.get("/api/incidents", params={"limit": 50, "include_demo": 1}).json()
    assert any(i["demo"] for i in data["items"])


# ---------------------------------------------------------------------------
# RBA entities
# ---------------------------------------------------------------------------
def test_rba_entities_exclude_demo_by_default(seeded, client):
    data = client.get("/api/rba/entities", params={"page_size": 50}).json()
    assert {e["entity_name"] for e in data["entities"]} == {"prod-user"}
    assert all(e["demo"] is False for e in data["entities"])


def test_rba_entities_include_demo_on_demand(seeded, client):
    data = client.get(
        "/api/rba/entities", params={"page_size": 50, "include_demo": 1}
    ).json()
    assert {e["entity_name"] for e in data["entities"]} == {"prod-user", "demo-user"}


def test_rba_profile_hides_demo_entities(seeded, client):
    resp = client.get("/api/rba/entities/user/demo-user")
    assert resp.status_code == 404
    resp = client.get("/api/rba/entities/user/demo-user?include_demo=1")
    assert resp.status_code == 200
    assert resp.json()["entity"]["entity_name"] == "demo-user"


def test_rba_profile_production_visible(seeded, client):
    resp = client.get("/api/rba/entities/user/prod-user")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------
def test_dashboard_summary_excludes_demo(seeded, client):
    data = client.get("/api/dashboard/summary").json()
    assert data["total_events"] == 1
    assert data["active_alerts"] == 1
    assert data["critical_threats"] == 1
    assert data["severity_counts"]["high"] == 1


def test_dashboard_summary_include_demo(seeded, client):
    data = client.get("/api/dashboard/summary", params={"include_demo": 1}).json()
    assert data["total_events"] == 2
    assert data["active_alerts"] == 2
    assert data["critical_threats"] == 2


def test_dashboard_timeline_excludes_demo(seeded, client):
    data = client.get("/api/dashboard/timeline", params={"hours": 24}).json()
    totals = sum(s["count"] for s in data["events"]) + sum(
        s["count"] for s in data["alerts"]
    )
    assert totals == 2  # one prod event + one prod alert
    data = client.get(
        "/api/dashboard/timeline", params={"hours": 24, "include_demo": 1}
    ).json()
    totals = sum(s["count"] for s in data["events"]) + sum(
        s["count"] for s in data["alerts"]
    )
    assert totals == 4


def test_dashboard_threat_categories_excludes_demo(seeded, client):
    data = client.get("/api/dashboard/threat-categories").json()
    assert sum(c["count"] for c in data) == 1
    data = client.get(
        "/api/dashboard/threat-categories", params={"include_demo": 1}
    ).json()
    assert sum(c["count"] for c in data) == 2


def test_dashboard_risk_distribution_excludes_demo(seeded, client):
    data = client.get("/api/dashboard/risk-distribution").json()
    assert sum(b["count"] for b in data) == 1
    data = client.get(
        "/api/dashboard/risk-distribution", params={"include_demo": 1}
    ).json()
    assert sum(b["count"] for b in data) == 2


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------
def test_search_excludes_demo_by_default(seeded, client):
    data = client.post("/api/search", json={"query": "index=alerts"}).json()
    assert data["total"] == 1
    d = data["columns"].index("demo")
    assert all(r[d] is False for r in data["rows"])


def test_search_include_demo_flag(seeded, client):
    data = client.post(
        "/api/search", json={"query": "index=alerts", "include_demo": 1}
    ).json()
    assert data["total"] == 2


def test_search_explicit_demo_filter_overrides_default(seeded, client):
    data = client.post("/api/search", json={"query": "index=alerts demo=true"}).json()
    assert data["total"] == 1
    d = data["columns"].index("demo")
    assert all(r[d] is True for r in data["rows"])
    data = client.post("/api/search", json={"query": "index=alerts demo=false"}).json()
    assert data["total"] == 1
    assert all(r[d] is False for r in data["rows"])


def test_search_events_exclude_demo_by_default(seeded, client):
    data = client.post("/api/search", json={"query": "event_id=4625"}).json()
    assert data["total"] == 1
    u = data["columns"].index("user")
    assert {r[u] for r in data["rows"]} == {"prod-user"}
    data = client.post(
        "/api/search", json={"query": "event_id=4625", "include_demo": 1}
    ).json()
    assert data["total"] == 2
    assert {r[u] for r in data["rows"]} == {"prod-user", "demo-user"}


# ---------------------------------------------------------------------------
# saved searches & dashboard render
# ---------------------------------------------------------------------------
def test_saved_search_run_excludes_demo(seeded, client, db):
    saved = SavedSearch(
        name="Prod alerts",
        description="",
        query="index=alerts severity=high",
        org="",
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    data = client.post(f"/api/saved/searches/{saved.id}/run").json()
    assert data["total"] == 1
    data = client.post(f"/api/saved/searches/{saved.id}/run?include_demo=1").json()
    assert data["total"] == 2


def test_saved_dashboard_render_excludes_demo(seeded, client, db):
    from backend.database.models import Dashboard

    dash = Dashboard(
        name="Prod dashboard",
        description="",
        panels=[{"id": "p1", "title": "Alerts", "query": "index=alerts"}],
        org="",
    )
    db.add(dash)
    db.commit()
    db.refresh(dash)
    data = client.get(f"/api/saved/dashboards/{dash.id}/render").json()
    assert sum(p.get("total", 0) for p in data["panels"]) == 1
    data = client.get(f"/api/saved/dashboards/{dash.id}/render?include_demo=1").json()
    assert sum(p.get("total", 0) for p in data["panels"]) == 2
