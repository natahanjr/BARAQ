"""Test self-service registration, admin verification, and account settings
(rename / change password) for both admin and analyst roles."""
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


def _register(client, username="jane", password="hunter2hunter2"):
    return client.post(
        "/api/auth/register",
        json={"username": username, "password": password, "full_name": "Jane Doe", "org": ""},
    )


def test_register_creates_pending_inactive_analyst(client):
    resp = _register(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["pending"] is True

    # Cannot sign in before verification - the response says it is pending.
    login = _login(client, "jane", "hunter2hunter2")
    assert login.status_code == 403
    assert "pending" in login.json()["detail"].lower()

    token = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(token)).json()["items"]
    jane = next(u for u in users if u["username"] == "jane")
    assert jane["role"] == "analyst"
    assert jane["is_active"] is False
    assert jane["registration_status"] == "pending"


def test_register_duplicate_username_conflicts(client):
    _register(client, username="dup")
    resp = _register(client, username="dup")
    assert resp.status_code == 409
    # Case-insensitive: 'DUP' collides with 'dup' (nat/Nat pitfall).
    resp = _register(client, username="DUP")
    assert resp.status_code == 409


def test_register_rejects_short_password(client):
    resp = client.post(
        "/api/auth/register",
        json={"username": "shortpw", "password": "short"},
    )
    assert resp.status_code == 422


def test_admin_approve_activates_account(client):
    _register(client, username="bob")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    bob = next(u for u in users if u["username"] == "bob")

    approved = client.post(f"/api/auth/users/{bob['id']}/approve", headers=_bearer_headers(admin))
    assert approved.status_code == 200
    assert approved.json()["is_active"] is True
    assert approved.json()["registration_status"] == ""

    login = _login(client, "bob", "hunter2hunter2")
    assert login.status_code == 200
    assert login.json()["token"]


def test_admin_reject_keeps_account_locked(client):
    _register(client, username="carol")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    carol = next(u for u in users if u["username"] == "carol")

    rejected = client.post(f"/api/auth/users/{carol['id']}/reject", headers=_bearer_headers(admin))
    assert rejected.status_code == 200
    assert rejected.json()["registration_status"] == "rejected"

    login = _login(client, "carol", "hunter2hunter2")
    assert login.status_code == 403
    assert "rejected" in login.json()["detail"].lower()


def test_approve_requires_admin(client):
    _register(client, username="dave")
    _register(client, username="analystx")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    dave = next(u for u in users if u["username"] == "dave")
    analystx = next(u for u in users if u["username"] == "analystx")

    client.post(f"/api/auth/users/{dave['id']}/approve", headers=_bearer_headers(admin))
    client.post(f"/api/auth/users/{analystx['id']}/approve", headers=_bearer_headers(admin))

    analyst_token = _login(client, "analystx", "hunter2hunter2")
    assert analyst_token.status_code == 200
    denied = client.post(
        f"/api/auth/users/{dave['id']}/approve",
        headers=_bearer_headers(analyst_token.json()["token"]),
    )
    assert denied.status_code == 403


def test_change_password_self_service(client):
    _register(client, username="erin")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    erin = next(u for u in users if u["username"] == "erin")
    client.post(f"/api/auth/users/{erin['id']}/approve", headers=_bearer_headers(admin))

    token = _login(client, "erin", "hunter2hunter2").json()["token"]
    # Wrong current password is rejected.
    bad = client.post(
        "/api/auth/settings/change-password",
        json={"current_password": "wrong", "new_password": "newpass1234"},
        headers=_bearer_headers(token),
    )
    assert bad.status_code == 403

    ok = client.post(
        "/api/auth/settings/change-password",
        json={"current_password": "hunter2hunter2", "new_password": "newpass1234"},
        headers=_bearer_headers(token),
    )
    assert ok.status_code == 200

    assert _login(client, "erin", "hunter2hunter2").status_code == 401
    assert _login(client, "erin", "newpass1234").status_code == 200


def test_rename_username_self_service(client):
    _register(client, username="frank")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    frank = next(u for u in users if u["username"] == "frank")
    client.post(f"/api/auth/users/{frank['id']}/approve", headers=_bearer_headers(admin))

    token = _login(client, "frank", "hunter2hunter2").json()["token"]

    # Conflict with the bootstrap admin, case-insensitive.
    conflict = client.post(
        "/api/auth/settings/rename",
        json={"current_password": "hunter2hunter2", "new_username": "ADMIN"},
        headers=_bearer_headers(token),
    )
    assert conflict.status_code == 409

    ok = client.post(
        "/api/auth/settings/rename",
        json={"current_password": "hunter2hunter2", "new_username": "franklin"},
        headers=_bearer_headers(token),
    )
    assert ok.status_code == 200
    assert ok.json()["username"] == "franklin"

    assert _login(client, "frank", "hunter2hunter2").status_code == 401
    assert _login(client, "franklin", "hunter2hunter2").status_code == 200


def test_settings_require_authentication(client):
    resp = client.post(
        "/api/auth/settings/change-password",
        json={"current_password": "x", "new_password": "newpass1234"},
    )
    assert resp.status_code in (401, 403)
    resp = client.post(
        "/api/auth/settings/rename",
        json={"current_password": "x", "new_username": "someone"},
    )
    assert resp.status_code in (401, 403)


def test_registration_and_approval_are_audited(client):
    _register(client, username="grace")
    admin = _login(client, "admin", "baraqadmin").json()["token"]
    users = client.get("/api/auth/users", headers=_bearer_headers(admin)).json()["items"]
    grace = next(u for u in users if u["username"] == "grace")
    client.post(f"/api/auth/users/{grace['id']}/approve", headers=_bearer_headers(admin))

    audit = client.get("/api/auth/audit", headers=_bearer_headers(admin)).json()["items"]
    actions = {e["action"] for e in audit}
    assert "user.registered" in actions
    assert "user.approved" in actions
