"""Test multi-user auth: login/logout, session tokens, user management, audit."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _ensure_bootstrap_admin():
    """Re-seed the bootstrap admin after each test wipes the users table."""
    from backend.auth import hash_password
    from backend.database.connection import SessionLocal
    from backend.database.models import User

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            db.add(User(
                username="admin",
                password_hash=hash_password("baraqadmin"),
                role="admin",
                is_active=True,
            ))
            db.commit()
    finally:
        db.close()
    yield


def _login(client, username, password):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def _bearer_headers(token):
    return {"Authorization": f"Bearer {token}"}


def test_logout_is_public(client):
    assert client.post("/api/auth/logout").status_code == 200


def test_login_success_returns_token(client):
    resp = _login(client, "admin", "baraqadmin")
    assert resp.status_code == 200
    data = resp.json()
    assert data["token"] and "." in data["token"]
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


def test_login_rejects_bad_password(client):
    resp = _login(client, "admin", "wrong-password")
    assert resp.status_code == 401


def test_login_rejects_unknown_user(client):
    resp = _login(client, "ghost", "whatever123")
    assert resp.status_code == 401


def test_login_records_audit_entry(client):
    from backend.database.connection import SessionLocal
    from backend.database.models import AuditLog

    _login(client, "admin", "baraqadmin")
    db = SessionLocal()
    try:
        actions = [e.action for e in db.query(AuditLog).all()]
    finally:
        db.close()
    assert "login" in actions


def test_me_returns_authenticated_user(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    resp = client.get("/api/auth/me", headers=_bearer_headers(token))
    assert resp.status_code == 200
    assert resp.json()["user"]["username"] == "admin"


def test_me_rejects_invalid_token(client):
    resp = client.get("/api/auth/me", headers=_bearer_headers("junk.token"))
    assert resp.status_code == 401


def test_token_grants_admin_access(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(token))
    assert users.status_code == 200
    assert any(u["username"] == "admin" for u in users.json()["items"])


def test_admin_creates_analyst_user(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    created = client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc2", "password": "hunter2hunter2", "role": "analyst", "full_name": "SOC Analyst 2"},
    )
    assert created.status_code == 200
    assert created.json()["role"] == "analyst"

    analyst_login = _login(client, "soc2", "hunter2hunter2")
    assert analyst_login.status_code == 200
    assert analyst_login.json()["user"]["role"] == "analyst"


def test_analyst_cannot_touch_users(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc3", "password": "hunter2hunter2", "role": "analyst"},
    )
    analyst = _login(client, "soc3", "hunter2hunter2").json()["token"]
    denied = client.get("/api/auth/users", headers=_bearer_headers(analyst))
    assert denied.status_code == 403


def test_disable_account_rejects_login(client):
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    user = client.post(
        "/api/auth/users",
        headers=_bearer_headers(admin),
        json={"username": "soc4", "password": "hunter2hunter2", "role": "analyst"},
    ).json()
    client.patch(
        f"/api/auth/users/{user['id']}",
        headers=_bearer_headers(admin),
        json={"is_active": False},
    )
    assert _login(client, "soc4", "hunter2hunter2").status_code == 403


def test_audit_endpoint_lists_login_events(client):
    _login(client, "admin", "baraqadmin")
    token = _login(client, "admin", "baraqadmin").json()["token"]
    audit = client.get("/api/auth/audit", headers=_bearer_headers(token))
    assert audit.status_code == 200
    actions = [e["action"] for e in audit.json()["items"]]
    assert "login" in actions


def test_admin_deletes_user(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    user = client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc_delete", "password": "hunter2hunter2", "role": "analyst"},
    ).json()
    deleted = client.delete(
        f"/api/auth/users/{user['id']}", headers=_bearer_headers(token)
    )
    assert deleted.status_code == 200
    assert deleted.json()["username"] == "soc_delete"
    gone = client.get("/api/auth/users", headers=_bearer_headers(token)).json()["items"]
    assert all(u["username"] != "soc_delete" for u in gone)
    assert _login(client, "soc_delete", "hunter2hunter2").status_code == 401


def test_delete_user_requires_admin(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    user = client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc_ast", "password": "hunter2hunter2", "role": "analyst"},
    ).json()
    analyst = _login(client, "soc_ast", "hunter2hunter2").json()["token"]
    assert client.delete(
        f"/api/auth/users/{user['id']}", headers=_bearer_headers(analyst)
    ).status_code == 403
    still_there = client.get("/api/auth/users", headers=_bearer_headers(token)).json()["items"]
    assert any(u["username"] == "soc_ast" for u in still_there)


def test_cannot_delete_own_account(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    me = client.get("/api/auth/me", headers=_bearer_headers(token)).json()["user"]
    assert client.delete(
        f"/api/auth/users/{me['id']}", headers=_bearer_headers(token)
    ).status_code == 400


def test_delete_records_audit_entry(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    user = client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc_audit", "password": "hunter2hunter2", "role": "analyst"},
    ).json()
    client.delete(f"/api/auth/users/{user['id']}", headers=_bearer_headers(token))
    audit = client.get("/api/auth/audit", headers=_bearer_headers(token)).json()["items"]
    assert any(e["action"] == "user.delete" for e in audit)


def test_clear_audit_empties_trail_and_logs_itself(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    before = client.get("/api/auth/audit", headers=_bearer_headers(token)).json()["items"]
    assert before
    cleared = client.post("/api/auth/audit/clear", headers=_bearer_headers(token))
    assert cleared.status_code == 200
    body = cleared.json()
    assert body["cleared"] >= len(before)
    assert body["report"]  # forced report was generated before erasing
    remaining = client.get("/api/auth/audit", headers=_bearer_headers(token)).json()["items"]
    assert len(remaining) == 1
    assert remaining[0]["action"] == "audit.clear"


def test_clear_audit_requires_admin(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc_clear", "password": "hunter2hunter2", "role": "analyst"},
    )
    analyst = _login(client, "soc_clear", "hunter2hunter2").json()["token"]
    assert client.post(
        "/api/auth/audit/clear", headers=_bearer_headers(analyst)
    ).status_code == 403


def test_clear_audit_writes_report_file(client):
    token = _login(client, "admin", "baraqadmin").json()["token"]
    body = client.post("/api/auth/audit/clear", headers=_bearer_headers(token)).json()
    assert body["cleared"] > 0
    assert body["report"]["file_path"].lower().endswith(".pdf")