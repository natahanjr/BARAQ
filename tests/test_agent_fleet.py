"""Agent fleet (roadmap 3.4): health, tags/grouping, overview, auto-update."""

from __future__ import annotations

from datetime import UTC

from fastapi.testclient import TestClient

from backend.main import app


def _fleet_client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


def _register_agent(client, agent_id="agent-dev", version="2.0.0", os_info="Windows"):
    from tests.fixtures import brute_force

    resp = client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={
            "records": brute_force()[:5],
            "host": "fleet-host-1",
            "agent_id": agent_id,
            "agent_version": version,
            "os_info": os_info,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_ingest_records_fleet_metadata():
    with _fleet_client() as client:
        _register_agent(client)
        rows = client.get("/api/endpoints").json()["items"]
        ep = next(r for r in rows if r["agent_id"] == "agent-dev")
        assert ep["agent_version"] == "2.0.0"
        assert ep["os_info"] == "Windows"
        assert ep["health_status"] == "ok"
        assert ep["tags"] == ""


def test_stale_agent_flagged():
    from datetime import datetime, timedelta

    from sqlalchemy import update

    from backend.database.connection import SessionLocal
    from backend.database.models import Endpoint

    with _fleet_client() as client:
        _register_agent(client)
        with SessionLocal() as db:
            db.execute(
                update(Endpoint)
                .where(Endpoint.agent_id == "agent-dev")
                .values(last_seen=datetime.now(UTC) - timedelta(minutes=10))
            )
            db.commit()
        rows = client.get("/api/endpoints").json()["items"]
        ep = next(r for r in rows if r["agent_id"] == "agent-dev")
        assert ep["health_status"] == "stale"

        overview = client.get("/api/endpoints/overview").json()
        assert overview["health"].get("stale", 0) >= 1
        assert "agent-dev" in overview["stale_agents"]


def test_tags_group_and_filter():
    with _fleet_client() as client:
        _register_agent(client)
        r = client.post(
            "/api/endpoints/agent-dev/tags",
            json={"tags": "dmz,web"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["tags"] == "dmz,web"

        tagged = client.get("/api/endpoints", params={"tag": "web"}).json()["items"]
        assert any(ep["agent_id"] == "agent-dev" for ep in tagged)

        overview = client.get("/api/endpoints/overview").json()
        assert overview["by_tag"].get("dmz") == 1
        assert overview["by_version"].get("2.0.0") >= 1


def test_update_command_lifecycle():
    with _fleet_client() as client:
        _register_agent(client)
        created = client.post(
            "/api/endpoints/agent-dev/commands",
            json={"action": "update_agent", "target": "2.1.0", "note": "rollout"},
        )
        assert created.status_code == 200, created.text
        cmd = created.json()
        assert cmd["action"] == "update_agent"

        ep = next(
            r
            for r in client.get("/api/endpoints").json()["items"]
            if r["agent_id"] == "agent-dev"
        )
        assert ep["update_status"] == "pending"

        pending = client.get(
            "/api/commands/pending", headers={"X-Agent-Key": "baraq-agent-dev"}
        ).json()["items"]
        assert any(c["id"] == cmd["id"] for c in pending)

        reported = client.post(
            f"/api/commands/{cmd['id']}/result",
            headers={"X-Agent-Key": "baraq-agent-dev"},
            json={"status": "success", "detail": "updated to 2.1.0"},
        )
        assert reported.status_code == 200, reported.text

        ep = next(
            r
            for r in client.get("/api/endpoints").json()["items"]
            if r["agent_id"] == "agent-dev"
        )
        assert ep["update_status"] == "current"


def test_failed_command_increments_errors():
    with _fleet_client() as client:
        _register_agent(client)
        created = client.post(
            "/api/endpoints/agent-dev/commands",
            json={"action": "block_ip", "target": "10.1.2.3"},
        ).json()
        client.post(
            f"/api/commands/{created['id']}/result",
            headers={"X-Agent-Key": "baraq-agent-dev"},
            json={"status": "failed", "detail": "netsh error"},
        )
        ep = next(
            r
            for r in client.get("/api/endpoints").json()["items"]
            if r["agent_id"] == "agent-dev"
        )
        assert ep["errors_total"] >= 1


def test_tags_requires_admin():
    from backend.main import app as _app

    with TestClient(_app, headers={"X-API-Key": "baraq-dev-analyst"}) as bare:
        r = bare.post("/api/endpoints/agent-dev/tags", json={"tags": "x"})
        assert r.status_code == 403
