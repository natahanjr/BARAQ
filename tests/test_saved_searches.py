"""Tests for saved searches & dashboards (backend/api/saved.py)."""

from __future__ import annotations


def _seed(db):
    from backend.api.system import run_pipeline
    from tests.fixtures import brute_force

    run_pipeline(db, brute_force())


def test_saved_search_crud_and_run(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    _seed(db)
    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}

    r = client.post(
        "/api/saved/searches",
        headers=headers,
        json={
            "name": "failed_logons",
            "description": "hunt",
            "query": "event_id=4625 | top 5 user",
            "earliest": "-30d",
        },
    )
    assert r.status_code == 200
    sid = r.json()["id"]

    r = client.get("/api/saved/searches", headers=headers)
    assert r.status_code == 200
    assert any(s["name"] == "failed_logons" for s in r.json()["searches"])

    r = client.post(f"/api/saved/searches/{sid}/run", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["columns"] == ["user", "count"]
    assert body["total"] >= 1

    r = client.patch(
        f"/api/saved/searches/{sid}", headers=headers, json={"description": "updated"}
    )
    assert r.status_code == 200
    assert r.json()["description"] == "updated"

    r = client.delete(f"/api/saved/searches/{sid}", headers=headers)
    assert r.status_code == 200
    r = client.get("/api/saved/searches", headers=headers)
    assert all(s["name"] != "failed_logons" for s in r.json()["searches"])


def test_saved_search_duplicate_rejected(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}
    body = {"name": "dup", "query": "event_id=1"}
    assert (
        client.post("/api/saved/searches", headers=headers, json=body).status_code
        == 200
    )
    assert (
        client.post("/api/saved/searches", headers=headers, json=body).status_code
        == 409
    )


def test_saved_search_org_scoping(db):
    from fastapi.testclient import TestClient

    from backend.database.models import SavedSearch
    from backend.main import app

    saved = SavedSearch(
        name="org_private",
        query="event_id=1",
        org="tenant-alpha",
        earliest="-24h",
        owner="someone",
    )
    db.add(saved)
    db.commit()

    client = TestClient(app)
    # Admin in scope "" does not see tenant-private searches.
    r = client.get("/api/saved/searches", headers={"X-API-Key": "baraq-dev-admin"})
    assert all(s["name"] != "org_private" for s in r.json()["searches"])


def test_dashboard_crud_and_render(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    _seed(db)
    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}

    saved = client.post(
        "/api/saved/searches",
        headers=headers,
        json={
            "name": "logon_stats",
            "query": "event_id=4625 | stats count by user | sort -count",
            "earliest": "-30d",
        },
    ).json()

    r = client.post(
        "/api/saved/dashboards",
        headers=headers,
        json={
            "name": "Auth Overview",
            "description": "logon dashboard",
            "panels": [
                {
                    "title": "Top users",
                    "saved_search_id": saved["id"],
                    "viz": "top",
                    "field": "user",
                    "limit": 5,
                    "cols": 2,
                },
                {
                    "title": "Total logons",
                    "saved_search_id": saved["id"],
                    "viz": "count",
                },
                {
                    "title": "Inline",
                    "query": "event_id=4625 | stats count by host | sort -count | limit 5",
                    "viz": "table",
                },
            ],
        },
    )
    assert r.status_code == 200
    did = r.json()["id"]

    r = client.get(f"/api/saved/dashboards/{did}/render", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["panels"]) == 3

    top = body["panels"][0]
    assert top["viz"] == "top"
    assert top["data"] and all("name" in p and "count" in p for p in top["data"])
    assert len(top["data"]) <= 5

    count = body["panels"][1]
    assert count["viz"] == "count"
    assert count["count"] >= 1

    table = body["panels"][2]
    assert table["columns"] == ["host", "count"]

    r = client.patch(
        f"/api/saved/dashboards/{did}",
        headers=headers,
        json={"description": "v2"},
    )
    assert r.status_code == 200
    assert r.json()["description"] == "v2"

    r = client.delete(f"/api/saved/dashboards/{did}", headers=headers)
    assert r.status_code == 200


def test_dashboard_panel_missing_saved_search(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}
    r = client.post(
        "/api/saved/dashboards",
        headers=headers,
        json={
            "name": "broken",
            "panels": [{"title": "gone", "saved_search_id": 9999, "viz": "table"}],
        },
    )
    assert r.status_code == 200
    did = r.json()["id"]
    r = client.get(f"/api/saved/dashboards/{did}/render", headers=headers)
    assert r.status_code == 200
    assert "error" in r.json()["panels"][0]


def test_dashboard_panel_invalid_query(db):
    from fastapi.testclient import TestClient

    from backend.main import app

    client = TestClient(app)
    headers = {"X-API-Key": "baraq-dev-admin"}
    r = client.post(
        "/api/saved/dashboards",
        headers=headers,
        json={
            "name": "badq",
            "panels": [{"title": "x", "query": "bogus_field=1", "viz": "table"}],
        },
    )
    did = r.json()["id"]
    r = client.get(f"/api/saved/dashboards/{did}/render", headers=headers)
    assert "error" in r.json()["panels"][0]
