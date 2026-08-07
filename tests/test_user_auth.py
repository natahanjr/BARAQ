"""Test multi-user auth: login/logout, session tokens, user management, audit."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "sentinel-dev-admin"}) as test_client:
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
                password_hash=hash_password("sentineladmin"),
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
    resp = _login(client, "admin", "sentineladmin")
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

    _login(client, "admin", "sentineladmin")
    db = SessionLocal()
    try:
        actions = [e.action for e in db.query(AuditLog).all()]
    finally:
        db.close()
    assert "login" in actions


def test_me_returns_authenticated_user(client):
    token = _login(client, "admin", "sentineladmin").json()["token"]
    resp = client.get("/api/auth/me", headers=_bearer_headers(token))
    assert resp.status_code == 200
    assert resp.json()["user"]["username"] == "admin"


def test_me_rejects_invalid_token(client):
    resp = client.get("/api/auth/me", headers=_bearer_headers("junk.token"))
    assert resp.status_code == 401


def test_token_grants_admin_access(client):
    token = _login(client, "admin", "sentineladmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(token))
    assert users.status_code == 200
    assert any(u["username"] == "admin" for u in users.json()["items"])


def test_admin_creates_analyst_user(client):
    token = _login(client, "admin", "sentineladmin").json()["token"]
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
    token = _login(client, "admin", "sentineladmin").json()["token"]
    client.post(
        "/api/auth/users",
        headers=_bearer_headers(token),
        json={"username": "soc3", "password": "hunter2hunter2", "role": "analyst"},
    )
    analyst = _login(client, "soc3", "hunter2hunter2").json()["token"]
    denied = client.get("/api/auth/users", headers=_bearer_headers(analyst))
    assert denied.status_code == 403


def test_disable_account_rejects_login(client):
    admin = _login(client, "admin", "sentineladmin").json()["token"]
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
    _login(client, "admin", "sentineladmin")
    token = _login(client, "admin", "sentineladmin").json()["token"]
    audit = client.get("/api/auth/audit", headers=_bearer_headers(token))
    assert audit.status_code == 200
    actions = [e["action"] for e in audit.json()["items"]]
    assert "login" in actions