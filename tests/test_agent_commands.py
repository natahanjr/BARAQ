"""Test the remote agent control channel (command queue -> agent -> result)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


def _ensure_agent(client):
    from tests.fixtures import brute_force

    resp = client.post(
        "/api/ingest",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={"records": brute_force(attempts=1)},
    )
    assert resp.status_code == 200
    return resp.json()["agent_id"]


def test_queue_command_requires_admin():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-analyst"}) as bare:
        assert (
            bare.post(
                "/api/endpoints/agent-dev/commands", json={"action": "escalate"}
            ).status_code
            == 403
        )


def test_queue_command_unknown_agent_404(client):
    resp = client.post(
        "/api/endpoints/does-not-exist/commands",
        json={"action": "escalate"},
    )
    assert resp.status_code == 404


def test_queue_command_validates_block_ip(client):
    _ensure_agent(client)
    resp = client.post(
        "/api/endpoints/agent-dev/commands",
        json={"action": "block_ip", "target": "not-an-ip"},
    )
    assert resp.status_code == 422


def test_pending_requires_agent_key(client):
    resp = client.get("/api/commands/pending")
    assert resp.status_code == 401
    assert "agent key" in resp.json()["detail"].lower()


def test_pending_rejects_unknown_agent_key(client):
    resp = client.get("/api/commands/pending", headers={"X-Agent-Key": "baraq-nope"})
    assert resp.status_code == 401


def test_full_command_lifecycle(client):
    _ensure_agent(client)

    created = client.post(
        "/api/endpoints/agent-dev/commands",
        json={
            "action": "kill_process",
            "target": "miner.exe",
            "note": "suspected cryptominer",
        },
    )
    assert created.status_code == 200
    cmd = created.json()
    assert cmd["status"] == "pending"
    assert cmd["agent_id"] == "agent-dev"

    pending = client.get(
        "/api/commands/pending", headers={"X-Agent-Key": "baraq-agent-dev"}
    ).json()["items"]
    assert any(c["id"] == cmd["id"] for c in pending)

    wrong_agent = client.post(
        f"/api/commands/{cmd['id']}/result",
        headers={"X-Agent-Key": "baraq-agent-laptop2"},
        json={"status": "success"},
    )
    assert wrong_agent.status_code == 404

    reported = client.post(
        f"/api/commands/{cmd['id']}/result",
        headers={"X-Agent-Key": "baraq-agent-dev"},
        json={"status": "success", "detail": "process terminated"},
    )
    assert reported.status_code == 200
    assert reported.json()["status"] == "success"

    pending = client.get(
        "/api/commands/pending", headers={"X-Agent-Key": "baraq-agent-dev"}
    ).json()["items"]
    assert all(c["id"] != cmd["id"] for c in pending)

    history = client.get("/api/commands", params={"status": "success"}).json()["items"]
    assert any(
        c["id"] == cmd["id"] and c["detail"] == "process terminated" for c in history
    )

    agent_history = client.get("/api/endpoints/agent-dev/commands").json()["items"]
    assert any(c["id"] == cmd["id"] for c in agent_history)
