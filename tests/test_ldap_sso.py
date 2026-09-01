"""Tests for LDAP/AD SSO (SC5b): group->role mapping, the login fallback
chain (local password -> LDAP -> auto-provision), and audit coverage.

The directory is faked by monkeypatching ``backend.ldap._authenticate_impl``
so the suite runs without a real LDAP server or the ldap3 package.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend import ldap as ldap_sso
from backend.totp import current_code

# ---------------------------------------------------------------------------
# Group -> role mapping (pure logic)
# ---------------------------------------------------------------------------


def test_admin_group_maps_to_admin():
    groups = ["CN=Domain Admins,CN=Users,DC=corp,DC=local"]
    assert ldap_sso._role_for(groups) == "admin"


def test_admin_group_by_cn_only():
    groups = ["CN=BARAQ Admins,OU=Groups,DC=corp,DC=local"]
    assert ldap_sso._role_for(groups) == "admin"


def test_case_insensitive_admin_match():
    groups = ["CN=domain admins,CN=Users,DC=corp,DC=local"]
    assert ldap_sso._role_for(groups) == "admin"


def test_non_admin_groups_default_to_analyst():
    groups = ["CN=Analysts,OU=Groups,DC=corp,DC=local", "CN=VPN Users,DC=corp,DC=local"]
    assert ldap_sso._role_for(groups) == "analyst"


def test_no_groups_defaults_to_analyst():
    assert ldap_sso._role_for([]) == "analyst"
    assert ldap_sso._role_for(None) == "analyst"


def test_group_names_normalises_dn_and_cn():
    names = ldap_sso._group_names(["CN=SOC Team,OU=Groups,DC=corp,DC=local"])
    assert names == ["CN=SOC Team,OU=Groups,DC=corp,DC=local", "SOC Team"]


def test_substring_match_does_not_grant_admin():
    """Regression: groups whose CN contains 'admin' as a substring must
    NOT grant admin. The previous implementation used
    ``admin_group.lower() in n`` which falsely matched
    ``Administrators (Read-Only)``, ``Helpdesk Admins Temp`` etc."""
    groups = [
        "CN=Administrators (Read-Only),OU=Groups,DC=corp,DC=local",
        "CN=Helpdesk Admins Temp,OU=Groups,DC=corp,DC=local",
        "CN=not-admin-but-related,OU=Groups,DC=corp,DC=local",
    ]
    assert ldap_sso._role_for(groups) == "analyst"


# ---------------------------------------------------------------------------
# Login flow with a fake directory
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


def _fake_directory(accounts: dict):
    """Return a _authenticate_impl replacement backed by a plain dict."""

    def impl(username: str, password: str):
        if username not in accounts:
            return None
        expected, full_name, role = accounts[username]
        if password != expected:
            return None
        groups = (
            ["CN=Domain Admins,DC=corp,DC=local"]
            if role == "admin"
            else ["CN=Analysts,DC=corp,DC=local"]
        )
        return {
            "username": username,
            "full_name": full_name,
            "role": role,
            "groups": groups,
        }

    return impl


@pytest.fixture()
def ldap_on(monkeypatch):
    monkeypatch.setattr(ldap_sso, "ldap_enabled", lambda: True)
    return monkeypatch


def _find_user(username: str):
    from backend.database.connection import SessionLocal
    from backend.database.models import User

    db = SessionLocal()
    try:
        return db.query(User).filter(User.username == username).first()
    finally:
        db.close()


def test_ldap_user_is_auto_provisioned_and_gets_role(client, ldap_on):
    ldap_on.setattr(
        ldap_sso,
        "_authenticate_impl",
        _fake_directory({"jdoe": ("CorpPass!42", "Jane Doe", "analyst")}),
    )

    resp = client.post(
        "/api/auth/login", json={"username": "jdoe", "password": "CorpPass!42"}
    )
    assert resp.status_code == 200, resp.text
    user = resp.json()["user"]
    assert user["username"] == "jdoe"
    assert user["role"] == "analyst"
    assert user["full_name"] == "Jane Doe"

    row = _find_user("jdoe")
    assert row is not None and row.role == "analyst"
    # The local password hash must be unusable: directory remains the only way in.
    from backend.auth import verify_password

    assert not verify_password("CorpPass!42", row.password_hash)


def test_ldap_admin_group_grants_admin_role(client, ldap_on):
    ldap_on.setattr(
        ldap_sso,
        "_authenticate_impl",
        _fake_directory({"jdoe": ("CorpPass!42", "Jane Doe", "admin")}),
    )
    resp = client.post(
        "/api/auth/login", json={"username": "jdoe", "password": "CorpPass!42"}
    )
    assert resp.status_code == 200
    assert resp.json()["user"]["role"] == "admin"


def test_wrong_ldap_password_is_rejected(client, ldap_on):
    ldap_on.setattr(
        ldap_sso,
        "_authenticate_impl",
        _fake_directory({"jdoe": ("CorpPass!42", "Jane Doe", "analyst")}),
    )
    resp = client.post(
        "/api/auth/login", json={"username": "jdoe", "password": "wrong-pass"}
    )
    assert resp.status_code == 401
    assert _find_user("jdoe") is None  # nothing provisioned on failure


def test_unknown_user_is_rejected(client, ldap_on):
    ldap_on.setattr(ldap_sso, "_authenticate_impl", lambda u, p: None)
    resp = client.post("/api/auth/login", json={"username": "ghost", "password": "x"})
    assert resp.status_code == 401


def test_directory_unavailable_falls_back_gracefully(client, ldap_on):
    def boom(username, password):
        raise ldap_sso.LDAPError("connection refused")

    ldap_on.setattr(ldap_sso, "_authenticate_impl", boom)
    resp = client.post("/api/auth/login", json={"username": "jdoe", "password": "x"})
    assert resp.status_code == 401  # never leak that the directory is down


def test_local_password_wins_over_ldap(client, ldap_on):
    # Even with LDAP enabled, an existing local account authenticates locally.
    ldap_on.setattr(ldap_sso, "_authenticate_impl", lambda u, p: None)
    resp = client.post(
        "/api/auth/login", json={"username": "admin", "password": "baraqadmin"}
    )
    assert resp.status_code == 200
    assert resp.json()["user"]["username"] == "admin"


def test_ldap_with_2fa_requires_challenge(client, ldap_on):
    ldap_on.setattr(
        ldap_sso,
        "_authenticate_impl",
        _fake_directory({"jdoe": ("CorpPass!42", "Jane Doe", "analyst")}),
    )

    # First login provisions the account.
    first = client.post(
        "/api/auth/login", json={"username": "jdoe", "password": "CorpPass!42"}
    )
    assert first.status_code == 200
    token = first.json()["token"]

    # Enable TOTP for the provisioned account.
    headers = {"Authorization": f"Bearer {token}"}
    setup = client.post("/api/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200
    secret = setup.json()["secret"]
    confirm = client.post(
        "/api/auth/mfa/confirm", headers=headers, json={"code": current_code(secret)}
    )
    assert confirm.status_code == 200

    # Next login must go through the MFA challenge step.
    again = client.post(
        "/api/auth/login", json={"username": "jdoe", "password": "CorpPass!42"}
    )
    assert again.status_code == 200
    data = again.json()
    assert data["mfa_required"] is True and data["challenge"]
    done = client.post(
        "/api/auth/mfa/verify",
        json={"challenge": data["challenge"], "code": current_code(secret)},
    )
    assert done.status_code == 200
    assert done.json()["token"]


def test_ldap_login_is_audited(client, ldap_on):
    ldap_on.setattr(
        ldap_sso,
        "_authenticate_impl",
        _fake_directory({"jdoe": ("CorpPass!42", "Jane Doe", "analyst")}),
    )
    client.post("/api/auth/login", json={"username": "jdoe", "password": "CorpPass!42"})

    from backend.database.connection import SessionLocal
    from backend.database.models import AuditLog

    db = SessionLocal()
    try:
        actions = [e.action for e in db.query(AuditLog).all()]
        assert "user.provisioned" in actions
        assert "login" in actions
    finally:
        db.close()
