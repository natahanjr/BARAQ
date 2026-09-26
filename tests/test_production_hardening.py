"""Regression tests for production security boundaries."""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient


def test_mfa_challenge_is_not_an_access_token(monkeypatch):
    from backend import auth

    monkeypatch.setattr(auth, "_is_token_revoked", lambda _jti: False)
    challenge = auth.create_mfa_challenge(1, "analyst")
    assert auth.verify_token(challenge) is None
    assert auth.verify_token(challenge, expected_type="access") is None
    assert auth.verify_mfa_challenge(challenge)["sub"] == "analyst"


def test_reset_token_is_not_an_access_token(monkeypatch):
    from backend import auth

    monkeypatch.setattr(auth, "_is_token_revoked", lambda _jti: False)
    token = auth.create_reset_token(1, "analyst")
    assert auth.verify_token(token) is None
    assert auth.verify_reset_token(token)["uid"] == 1


def test_missing_token_type_is_rejected(monkeypatch):
    import base64
    import hashlib
    import hmac
    import json

    from backend import auth

    monkeypatch.setattr(auth, "_is_token_revoked", lambda _jti: False)
    payload = {
        "uid": 1,
        "sub": "analyst",
        "role": "admin",
        "org": "",
        "iat": 1,
        "exp": 4_102_444_800,
        "jti": "legacy",
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signature = hmac.new(auth._token_secret(), body.encode(), hashlib.sha256).hexdigest()
    assert auth.verify_token(f"{body}.{signature}") is None


@pytest.mark.parametrize(
    ("action", "target"),
    [
        ("kill_process", "miner.exe; Write-Output INJECTED"),
        ("quarantine", "C:\\Temp\\file.txt'; Write-Output INJECTED"),
        ("isolate", "host; Write-Output INJECTED"),
        ("disable_account", "user'; Write-Output INJECTED"),
        ("update_agent", "../../Windows/Temp"),
        ("block_ip", "999.999.999.999"),
    ],
)
def test_agent_command_targets_reject_shell_grammar(action, target):
    from backend.api.endpoints import _validate_target
    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        _validate_target(action, target)


def test_realtime_hub_filters_tenant_messages():
    from backend.realtime import BroadcastHub

    async def scenario():
        hub = BroadcastHub()
        loop = asyncio.get_running_loop()
        hub.bind(loop)
        tenant_id, tenant_queue = await hub.connect("tenant-a", "analyst")
        other_id, other_queue = await hub.connect("tenant-b", "analyst")
        hub.publish({"type": "alert", "payload": {"org": "tenant-a", "id": 1}})
        await asyncio.sleep(0.05)
        assert tenant_queue.qsize() == 1
        assert other_queue.qsize() == 0
        await hub.disconnect(tenant_id)
        await hub.disconnect(other_id)

    asyncio.run(scenario())


def test_report_html_escapes_alert_values():
    from backend.reports.exporters import _render_html

    body = _render_html(
        {
            "title": "<script>alert(1)</script>",
            "summary": {},
            "alerts": [
                {
                    "name": "<img src=x onerror=alert(1)>",
                    "severity": "high",
                    "mitre_id": "T1059",
                    "mitre_tactic": "Execution",
                    "status": "open",
                }
            ],
        }
    )
    assert "<script>" not in body
    assert "<img src=x" not in body
    assert "&lt;script&gt;" in body


def test_report_download_requires_authentication():
    from backend.main import app

    with TestClient(app) as client:
        response = client.get("/api/reports/1/download")
    assert response.status_code == 401


def _seed_tenant_entities(db):
    """One host per tenant plus an alert on each host."""
    from datetime import UTC, datetime

    from backend.database.models import Alert, AlertEventLink, EntityNode, NormalizedEvent

    rows = {}
    for org, host in (("acme", "acme-ws-1"), ("globex", "globex-ws-1")):
        event = NormalizedEvent(
            source="test",
            event_id=4625,
            category="logon",
            severity="medium",
            message="failed logon",
            user="admin",
            host=host,
            org=org,
            timestamp=datetime.now(UTC),
        )
        db.add(event)
        db.flush()
        alert = Alert(
            name=f"{org} brute force",
            severity="high",
            status="open",
            org=org,
            host=host,
            rule="brute_force",
            evidence=f"{org} only",
        )
        db.add(alert)
        db.flush()
        db.add(AlertEventLink(alert_id=alert.id, event_id=event.id))
        node = EntityNode(kind="device", name=host, display_name=host, risk_score=80.0)
        db.add(node)
        db.flush()
        rows[org] = (host, alert)
    db.commit()
    return rows


def _analyst_headers(db, username: str, org: str) -> dict:
    from backend.auth import create_token, hash_password
    from backend.database.models import User

    user = User(
        username=username,
        password_hash=hash_password("baraq-test-password"),
        role="analyst",
        full_name=username,
        org=org,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"Authorization": f"Bearer {create_token(user.id, user.username, user.role, user.org)}"}


def test_entity_graph_is_tenant_scoped(db):
    """An analyst only sees entities from their own telemetry."""
    from backend.main import app

    seeded = _seed_tenant_entities(db)
    acme_host, _ = seeded["acme"]
    globex_host, _ = seeded["globex"]
    headers = _analyst_headers(db, "graph-analyst", "acme")

    with TestClient(app, headers=headers) as client:
        own = client.get(f"/api/entities/device/{acme_host}")
        assert own.status_code == 200, own.text
        assert own.json()["entity"]["name"] == acme_host
        # Alerts attached to the entity come from this tenant only.
        assert all(a["org"] == "acme" for a in own.json()["related_alerts"])

        foreign = client.get(f"/api/entities/device/{globex_host}")
        assert foreign.status_code == 404

        listing = client.get("/api/entities", params={"limit": 100})
        assert listing.status_code == 200
        names = {i["name"] for i in listing.json()["items"]}
        assert acme_host in names
        assert globex_host not in names

        graph = client.get(
            "/api/entities/graph",
            params={"center_kind": "device", "center_name": acme_host},
        )
        assert graph.status_code == 200
        assert all(n["name"] in names for n in graph.json()["nodes"])


def test_admin_entity_view_is_unrestricted(db):
    from backend.main import app

    seeded = _seed_tenant_entities(db)
    acme_host, _ = seeded["acme"]
    globex_host, _ = seeded["globex"]

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        own = client.get(f"/api/entities/device/{globex_host}")
        assert own.status_code == 200
        assert own.json()["entity"]["name"] == globex_host
        # The central admin scope sees both tenants.
        listing = client.get("/api/entities", params={"limit": 100})
        names = {i["name"] for i in listing.json()["items"]}
        assert {acme_host, globex_host} <= names


def test_report_schedule_recipients_hidden_from_analysts(db):
    from backend.api.reports import list_schedules
    from backend.database.models import ReportSchedule

    db.add(
        ReportSchedule(
            name="weekly",
            report_type="executive",
            fmt="pdf",
            every_hours=24,
            hour_of_day=7,
            email_to="soc-lead@example.com",
            enabled=True,
        )
    )
    db.commit()

    class _AnalystReq:
        class state:  # noqa: N801
            api_role = "analyst"
            token_user = {"role": "analyst", "org": "acme"}

    analyst_view = list_schedules(_AnalystReq(), db)["items"]
    assert analyst_view and all(not i["email_to"] for i in analyst_view)
    assert all(i["email_to_set"] for i in analyst_view)

    class _AdminReq:
        class state:  # noqa: N801
            api_role = "admin"
            token_user = None

    admin_view = list_schedules(_AdminReq(), db)["items"]
    assert any(i["email_to"] == "soc-lead@example.com" for i in admin_view)
