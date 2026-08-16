"""Multi-tenant ("org") scoping tests.

An analyst may only read/act on records tagged with their organization;
admins (and API keys) see everything. The ingest channel attaches the
organization configured for the reporting agent.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from backend.api.system import run_pipeline
from backend.auth import create_token, hash_password
from backend.database.connection import SessionLocal
from backend.database.models import Alert, Endpoint, NormalizedEvent, User
from tests.fixtures import brute_force


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _make_user(db, username: str, role: str = "analyst", org: str = "") -> User:
    user = User(
        username=username,
        password_hash=hash_password("baraq-test-password"),
        role=role,
        full_name=username,
        org=org,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _token(user: User) -> str:
    return create_token(user.id, user.username, user.role, user.org)


def _headers(user: User) -> dict:
    return {"Authorization": f"Bearer {_token(user)}"}


@pytest.fixture(scope="module")
def admin_client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as c:
        yield c


# ---------------------------------------------------------------------------
# pipeline attribution
# ---------------------------------------------------------------------------


def test_pipeline_attaches_org_to_events_and_alerts(db):
    run_pipeline(db, brute_force(), org="univ-a")
    assert db.scalar(select(func.count(NormalizedEvent.id))) > 0
    assert (
        db.scalar(
            select(func.count(NormalizedEvent.id)).where(NormalizedEvent.org == "univ-a")
        )
        == db.scalar(select(func.count(NormalizedEvent.id)))
    )
    assert db.scalar(select(func.count(Alert.id))) > 0
    assert (
        db.scalar(
            select(func.count(Alert.id)).where(Alert.org == "univ-a")
        )
        == db.scalar(select(func.count(Alert.id)))
    )


def test_pipeline_default_org_is_empty(db):
    run_pipeline(db, brute_force(), org="")
    assert db.scalar(select(func.count(Alert.id))) > 0
    assert db.scalar(select(func.count(Alert.id)).where(Alert.org == "")) == db.scalar(
        select(func.count(Alert.id))
    )


# ---------------------------------------------------------------------------
# ingest attribution via BARAQ_AGENT_ORGS mapping
# ---------------------------------------------------------------------------


def test_ingest_attributes_org_from_agent_mapping(admin_client, monkeypatch):
    import backend.config as config

    monkeypatch.setitem(config.AGENT_ORGS, "agent-dev", "univ-a")
    body = {
        "records": brute_force(8),
        "host": "pc-1",
    }
    resp = admin_client.post(
        "/api/ingest",
        json=body,
        headers={"X-Agent-Key": "baraq-agent-dev"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["org"] == "univ-a"

    with SessionLocal() as s:
        events = s.scalars(select(NormalizedEvent).where(NormalizedEvent.org == "univ-a")).all()
        assert events, "ingested events must carry the agent org"
        ep = s.get(Endpoint, "agent-dev")
        assert ep is not None and ep.org == "univ-a"
        alerts = s.scalars(select(Alert).where(Alert.org == "univ-a")).all()
        assert alerts, "ingested events should have produced org-scoped alerts"


# ---------------------------------------------------------------------------
# API enforcement
# ---------------------------------------------------------------------------


@pytest.fixture()
def seeded(db):
    """One alert per tenant so scoping is observable."""
    run_pipeline(db, brute_force(8), org="univ-a")
    run_pipeline(db, brute_force(8), org="univ-b")
    run_pipeline(db, brute_force(8), org="")
    return db


def test_alerts_are_scoped_per_org(seeded, admin_client):
    admin = admin_client.get("/api/alerts")
    assert admin.status_code == 200
    total = admin.json()["total"]
    assert total > 0, "admin should see alerts"

    analyst_a = _make_user(seeded, "analyst-a", org="univ-a")
    analyst_b = _make_user(seeded, "analyst-b", org="univ-b")

    resp_a = admin_client.get("/api/alerts", headers=_headers(analyst_a))
    assert resp_a.status_code == 200
    items_a = resp_a.json()["items"]
    assert items_a, "analyst should see their own org's alerts"
    assert all(a["org"] == "univ-a" for a in items_a)

    resp_b = admin_client.get("/api/alerts", headers=_headers(analyst_b))
    assert all(a["org"] == "univ-b" for a in resp_b.json()["items"])
    # identical seeded scenarios -> identical per-org totals (two-phase
    # detection completes correlation chains within the same pass, so each
    # org has a base alert plus its chain alert - never merged across orgs).
    assert resp_b.json()["total"] == resp_a.json()["total"]

    # admin sees the union of every org's alerts
    univ_c_count = db_scalar(select(func.count(Alert.id)).where(Alert.org == ""))
    assert total == resp_a.json()["total"] + resp_b.json()["total"] + univ_c_count


def test_alert_detail_is_404_across_orgs(seeded, admin_client):
    org_a_alert = db_scalar(
        select(Alert).where(Alert.org == "univ-a")
    )
    analyst_b = _make_user(seeded, "analyst-bb", org="univ-b")
    resp = admin_client.get(f"/api/alerts/{org_a_alert.id}", headers=_headers(analyst_b))
    assert resp.status_code == 404
    own = admin_client.get(f"/api/alerts/{org_a_alert.id}", headers=_headers(_make_user(seeded, "analyst-aa", org="univ-a")))
    assert own.status_code == 200


def test_alert_queries_are_scoped_by_org(seeded, db):
    analyst_a = _make_user(db, "analyst-count", org="univ-a")
    total_a = db.scalar(select(func.count(Alert.id)).where(Alert.org == "univ-a"))
    total_all = db.scalar(select(func.count(Alert.id)))
    from backend.analyzers import dashboard

    with SessionLocal() as s:
        assert dashboard.dashboard_summary(s, org="univ-a")["active_alerts"] == total_a
        assert dashboard.dashboard_summary(s)["active_alerts"] == total_all


def db_scalar(select_stmt):
    with SessionLocal() as s:
        return s.scalar(select_stmt)


# ---------------------------------------------------------------------------
# fleet (endpoints) scoping
# ---------------------------------------------------------------------------


def test_endpoints_are_scoped_per_org(seeded, db, admin_client):
    with SessionLocal() as s:
        s.add(Endpoint(agent_id="ep-a", host="host-a", org="univ-a", records_total=1,
                       events_total=1, alerts_total=0))
        s.add(Endpoint(agent_id="ep-b", host="host-b", org="univ-b", records_total=1,
                       events_total=1, alerts_total=0))
        s.commit()

    analyst_a = _make_user(db, "endpoint-analyst", org="univ-a")
    resp = admin_client.get("/api/endpoints", headers=_headers(analyst_a))
    assert resp.status_code == 200
    ids = [ep["agent_id"] for ep in resp.json()["items"]]
    assert "ep-a" in ids and "ep-b" not in ids


def test_admin_can_narrow_scope_via_header(seeded, admin_client):
    univ_a_count = db_scalar(select(func.count(Alert.id)).where(Alert.org == "univ-a"))
    resp = admin_client.get("/api/alerts", headers={"X-Org": "univ-a"})
    assert resp.status_code == 200
    assert resp.json()["total"] == univ_a_count
    assert resp.json()["total"] > 0
    assert all(a["org"] == "univ-a" for a in resp.json()["items"])


def test_tenant_scope_helper():
    """Direct checks of the security helper's three branches."""
    from fastapi import Request

    def req(**extra):
        scope = dict(
            type="http", method="GET", path="/", scheme="http",
            query_string=b"", headers=[(b"host", b"test")],
        )
        for k, v in extra.items():
            scope[k] = v
        return Request(scope)

    from backend.security import tenant_scope

    assert tenant_scope(req(state={"api_role": "admin"})) is None
    assert tenant_scope(req(state={"api_role": "analyst", "token_user": {"role": "analyst", "org": "univ-a"}})) == "univ-a"
    assert tenant_scope(req(state={"api_role": "analyst"})) == ""
    # Admins can narrow via X-Org; nobody else can widen.
    scoped = req(state={"api_role": "admin"})
    scoped.scope["headers"] = [(b"host", b"test"), (b"x-org", b"univ-a")]
    assert tenant_scope(scoped) == "univ-a"
    wide = req(state={"api_role": "analyst", "token_user": {"role": "analyst", "org": "univ-b"}})
    wide.scope["headers"] = [(b"host", b"test"), (b"x-org", b"univ-a")]
    assert tenant_scope(wide) == "univ-b"