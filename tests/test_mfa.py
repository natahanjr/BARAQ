"""Tests for TOTP 2FA: secret/code primitives and the login MFA flow."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from backend.totp import (
    current_code,
    generate_secret,
    provisioning_uri,
    verify_code,
)

# ---------------------------------------------------------------------------
# TOTP primitives
# ---------------------------------------------------------------------------


def test_secret_is_base32_and_unique():
    a, b = generate_secret(), generate_secret()
    assert len(a) == 32 and len(b) == 32
    assert a != b
    assert set(a) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def test_current_code_verifies_within_window():
    secret = generate_secret()
    code = current_code(secret)
    assert verify_code(secret, code)
    # ±30 s drift still accepted (window = ±1 step)
    assert verify_code(secret, code, at=time.time() + 29)
    assert verify_code(secret, code, at=time.time() - 29)


def test_wrong_code_rejected():
    secret = generate_secret()
    assert not verify_code(secret, "000000")
    assert not verify_code(secret, "")
    assert not verify_code(secret, "12345")
    assert not verify_code(secret, "abcdef")


def test_code_changes_over_time():
    secret = generate_secret()
    codes = {current_code(secret, at=time.time() + i * 60) for i in range(3)}
    assert len(codes) == 3  # distinct steps produce distinct codes


def test_provisioning_uri_shape():
    uri = provisioning_uri("alice", "JBSWY3DPEHPK3PXP", issuer="BARAQ")
    assert uri.startswith("otpauth://totp/")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
    assert "issuer=BARAQ" in uri
    assert "alice" in uri


# ---------------------------------------------------------------------------
# Login flow with MFA
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _bootstrap_admin():
    from backend.auth import hash_password
    from backend.database.connection import SessionLocal
    from backend.database.models import User

    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == "admin").first():
            db.add(
                User(
                    username="admin",
                    password_hash=hash_password("baraqadmin"),
                    role="admin",
                    is_active=True,
                )
            )
            db.commit()
    finally:
        db.close()


def _admin_login(client, password="baraqadmin"):
    return client.post(
        "/api/auth/login",
        json={"username": "admin", "password": password},
    )


def _auth_headers(client, password="baraqadmin"):
    """Log in (completing the MFA step if needed) and return Bearer headers."""
    resp = _admin_login(client, password)
    if resp.status_code != 200:
        raise AssertionError(f"login failed: {resp.status_code} {resp.text}")
    data = resp.json()
    if data.get("token"):
        return {"Authorization": f"Bearer {data['token']}"}
    if data.get("mfa_required"):
        secret = _secret_of("admin")
        code = current_code(secret)
        done = client.post(
            "/api/auth/mfa/verify",
            json={"challenge": data["challenge"], "code": code},
        )
        if done.status_code != 200:
            raise AssertionError(f"mfa verify failed: {done.status_code} {done.text}")
        return {"Authorization": f"Bearer {done.json()['token']}"}
    raise AssertionError(f"unexpected login response: {data}")


def _enable_2fa(client):
    """Run the full provisioning flow for the admin user and return the secret."""
    headers = _auth_headers(client)
    setup = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    code = current_code(secret)
    conf = client.post("/api/auth/mfa/confirm", headers=headers, json={"code": code})
    assert conf.status_code == 200
    assert conf.json()["totp_enabled"] is True
    return secret


def test_login_without_2fa_returns_token(client):
    resp = _admin_login(client)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("token")
    assert data["user"]["totp_enabled"] is False


def test_mfa_enabled_login_requires_challenge_then_code(client):
    _enable_2fa(client)

    # Step 1: password is correct but no session token is issued.
    resp = _admin_login(client)
    assert resp.status_code == 200
    data = resp.json()
    assert data["mfa_required"] is True
    assert "challenge" in data
    assert "token" not in data or not data["token"]

    # Wrong code is rejected.
    bad = client.post(
        "/api/auth/mfa/verify", json={"challenge": data["challenge"], "code": "000000"}
    )
    assert bad.status_code == 401

    # Correct code exchanges the challenge for a real session token.
    code = current_code(_secret_of("admin"))
    ok = client.post(
        "/api/auth/mfa/verify", json={"challenge": data["challenge"], "code": code}
    )
    assert ok.status_code == 200
    assert ok.json()["token"]
    assert ok.json()["user"]["totp_enabled"] is True


def test_2fa_verify_does_not_accept_full_session_token(client):
    _enable_2fa(client)

    # Get a real session token (password + TOTP).
    headers = _auth_headers(client)
    session_token = headers["Authorization"].replace("Bearer ", "")

    # A full session token is NOT a valid challenge (no "mfa" claim).
    code = current_code(_secret_of("admin"))
    bad = client.post(
        "/api/auth/mfa/verify", json={"challenge": session_token, "code": code}
    )
    assert bad.status_code == 401

    # An expired/bogus challenge is likewise rejected.
    bogus = client.post(
        "/api/auth/mfa/verify", json={"challenge": "bogus.token", "code": code}
    )
    assert bogus.status_code == 401


def test_2fa_verify_works_on_fresh_session_without_api_key(client):
    """A brand-new client (no session cookie, no API key) must be able to
    complete the MFA login step. Guards the API-key middleware exemption
    for /api/auth/mfa/verify in backend/main.py: the step happens BEFORE
    any session token exists, so it must not require X-API-Key."""
    from backend.main import app

    with TestClient(app) as fresh:
        _enable_2fa(fresh)  # login + setup + confirm round-trip in the fresh jar
        fresh.cookies.clear()  # simulate a brand-new browser: no session cookie
        login = fresh.post(
            "/api/auth/login", json={"username": "admin", "password": "baraqadmin"}
        )
        data = login.json()
        assert data["mfa_required"] is True and data["challenge"]
        # This request carries no session cookie and no API key — the
        # middleware must let it through (like /api/auth/login).
        code = current_code(_secret_of("admin"))
        ok = fresh.post(
            "/api/auth/mfa/verify", json={"challenge": data["challenge"], "code": code}
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["token"]


def test_mfa_disable_requires_valid_code(client):
    _enable_2fa(client)
    headers = _auth_headers(client)

    # Wrong code cannot disable 2FA.
    bad = client.post("/api/auth/mfa/disable", headers=headers, json={"code": "000000"})
    assert bad.status_code == 401

    code = current_code(_secret_of("admin"))
    ok = client.post("/api/auth/mfa/disable", headers=headers, json={"code": code})
    assert ok.status_code == 200
    assert ok.json()["totp_enabled"] is False

    # Login no longer requires MFA.
    resp = _admin_login(client)
    assert "token" in resp.json() and resp.json()["token"]


def test_mfa_setup_does_not_enable_without_confirm(client):
    from backend.database.connection import SessionLocal
    from backend.database.models import User

    headers = _auth_headers(client)
    setup = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        assert user.totp_enabled is False  # secret staged, not activated
        assert user.totp_secret == setup.json()["secret"]
    finally:
        db.close()


def _secret_of(username: str) -> str:
    from backend.database.connection import SessionLocal
    from backend.database.models import User

    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first().totp_secret
    finally:
        db.close()
