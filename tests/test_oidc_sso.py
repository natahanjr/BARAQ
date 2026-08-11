"""Tests for OIDC SSO (SC5c): id_token crypto validation, claim mapping, and
the /oidc/login + /oidc/callback endpoint flow against a fake provider.

The provider is faked by monkeypatching ``backend.oidc._http_json`` (returns
the discovery document + JWKS) and ``exchange_code``. The id_token is a real
RS256-signed JWT, so signature/claim validation is exercised end-to-end.
"""
from __future__ import annotations

import base64
import json
import time

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from backend import oidc as oidc_sso


# ---------------------------------------------------------------------------
# Helpers: build a fake provider's keys and sign real JWTs
# ---------------------------------------------------------------------------

_ISSUER = "https://idp.corp.local"
_CLIENT_ID = "baraq-soc"


@pytest.fixture(scope="module")
def provider_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": "test-key-1",
        "use": "sig",
        "alg": "RS256",
        "n": b64u(n),
        "e": b64u(e),
    }
    return {
        "private_key": private_key,
        "jwk": jwk,
        "b64u": b64u,
    }


def _make_id_token(provider_keys, nonce, claims_extra=None, sign=True,
                   alg="RS256", kid="test-key-1", iss=_ISSUER, aud=_CLIENT_ID):
    """Produce a signed RS256 id_token with sane defaults."""
    private_key, b64u = provider_keys["private_key"], provider_keys["b64u"]
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "sub-12345",
        "preferred_username": "jdoe",
        "name": "Jane Doe",
        "exp": now + 300,
        "iat": now - 5,
        "nbf": now - 5,
        "nonce": nonce,
        **(claims_extra or {}),
    }
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(claims).encode())}"
    if not sign:
        return f"{signing_input}.AAAA"
    sig = private_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64u(sig)}"


@pytest.fixture()
def fake_provider(monkeypatch, provider_keys):
    """Point the OIDC adapter at an in-memory provider (discovery + JWKS)."""
    doc = {
        "issuer": _ISSUER,
        "authorization_endpoint": "https://idp.corp.local/authorize",
        "token_endpoint": "https://idp.corp.local/token",
        "jwks_uri": "https://idp.corp.local/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }
    jwks = {"keys": [provider_keys["jwk"]]}
    oidc_sso._cached_docs.clear()

    def fake_http_json(url, timeout=10):
        if url.endswith("/.well-known/openid-configuration"):
            return doc
        if url.endswith("/jwks"):
            return jwks
        raise AssertionError(f"unexpected URL fetched: {url}")

    monkeypatch.setattr(oidc_sso, "_http_json", fake_http_json)
    monkeypatch.setattr(oidc_sso, "OIDC_CLIENT_ID", _CLIENT_ID)
    monkeypatch.setattr(oidc_sso, "OIDC_ISSUER", _ISSUER)
    monkeypatch.setattr(oidc_sso, "OIDC_ENABLED", True)
    monkeypatch.setattr(oidc_sso, "OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(oidc_sso, "OIDC_REDIRECT_PATH", "/api/auth/oidc/callback")
    return doc


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------


def test_profile_from_claims_analyst():
    profile = oidc_sso.profile_from_claims({
        "preferred_username": "jdoe",
        "name": "Jane Doe",
        "groups": ["SOC Analysts"],
    })
    assert profile == {"username": "jdoe", "full_name": "Jane Doe", "role": "analyst", "groups": ["SOC Analysts"]}


def test_profile_from_claims_admin_group():
    profile = oidc_sso.profile_from_claims({
        "preferred_username": "sysadmin",
        "groups": ["Domain Admins"],
    })
    assert profile["role"] == "admin"


def test_profile_from_claims_uses_sub_fallback():
    profile = oidc_sso.profile_from_claims({"sub": "ABC-123", "groups": []})
    assert profile["username"] == "abc-123"


def test_pkce_pair_shape():
    verifier, challenge = oidc_sso.generate_pkce_pair()
    assert len(verifier) > 40 and challenge  # 64 bytes, base64url-encoded SHA-256


# ---------------------------------------------------------------------------
# id_token validation (real RS256 signatures)
# ---------------------------------------------------------------------------


def test_valid_id_token_accepted(fake_provider, provider_keys):
    claims = oidc_sso.validate_id_token(_make_id_token(provider_keys, "nonce-1"), "nonce-1")
    assert claims["preferred_username"] == "jdoe"


def test_wrong_nonce_rejected(fake_provider, provider_keys):
    with pytest.raises(oidc_sso.OIDCError, match="nonce"):
        oidc_sso.validate_id_token(_make_id_token(provider_keys, "nonce-1"), "nonce-2")


def test_wrong_issuer_rejected(fake_provider, provider_keys):
    token = _make_id_token(provider_keys, "n", iss="https://evil.example")
    with pytest.raises(oidc_sso.OIDCError, match="issuer"):
        oidc_sso.validate_id_token(token, "n")


def test_wrong_audience_rejected(fake_provider, provider_keys):
    token = _make_id_token(provider_keys, "n", aud="some-other-app")
    with pytest.raises(oidc_sso.OIDCError, match="audience"):
        oidc_sso.validate_id_token(token, "n")


def test_expired_token_rejected(fake_provider, provider_keys):
    token = _make_id_token(provider_keys, "n", claims_extra={"exp": int(time.time()) - 60})
    with pytest.raises(oidc_sso.OIDCError, match="expired"):
        oidc_sso.validate_id_token(token, "n")


def test_tampered_signature_rejected(fake_provider, provider_keys):
    token = _make_id_token(provider_keys, "n", sign=False)
    with pytest.raises(oidc_sso.OIDCError, match="signature"):
        oidc_sso.validate_id_token(token, "n")


def test_unsupported_alg_rejected(fake_provider, provider_keys):
    token = _make_id_token(provider_keys, "n", alg="none")
    with pytest.raises(oidc_sso.OIDCError):
        oidc_sso.validate_id_token(token, "n")


# ---------------------------------------------------------------------------
# Endpoint flow (fake provider serving the code exchange)
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
            db.add(User(
                username="admin",
                password_hash=hash_password("baraqadmin"),
                role="admin",
                is_active=True,
            ))
            db.commit()
    finally:
        db.close()


def test_oidc_login_redirects_to_provider(client, fake_provider, monkeypatch):
    monkeypatch.setattr(oidc_sso, "oidc_enabled", lambda: True)
    resp = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://idp.corp.local/authorize?")
    assert "code_challenge_method=S256" in location
    assert "state=" in location and "nonce=" in location
    # The flow cookie is set so the callback can reconstruct state.
    assert resp.headers.get("set-cookie") and "baraq_oidc" in resp.headers["set-cookie"]


def test_oidc_callback_rejects_bad_state(client, fake_provider, monkeypatch):
    monkeypatch.setattr(oidc_sso, "oidc_enabled", lambda: True)
    resp = client.get("/api/auth/oidc/callback?code=x&state=forged", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"


def _run_full_oidc_login(client, provider_keys, monkeypatch, group=None):
    """Simulate: /oidc/login -> provider approves -> /oidc/callback."""
    monkeypatch.setattr(oidc_sso, "oidc_enabled", lambda: True)

    step1 = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert step1.status_code == 302
    import urllib.parse
    query = urllib.parse.parse_qs(urllib.parse.urlparse(step1.headers["location"]).query)
    state, nonce = query["state"][0], query["nonce"][0]

    def fake_exchange(code, verifier, base_url):
        # The verifier issued at /oidc/login is what we must echo back.
        claims = {"preferred_username": "jdoe", "name": "Jane Doe"}
        if group:
            claims["groups"] = [group]
        return {"id_token": _make_id_token(provider_keys, nonce, claims)}

    monkeypatch.setattr(oidc_sso, "exchange_code", fake_exchange)

    step2 = client.get(f"/api/auth/oidc/callback?code=abc123&state={state}", follow_redirects=False)
    assert step2.status_code == 302
    assert step2.headers["location"] == "/"
    assert "baraq_session=" in step2.headers.get("set-cookie", "")
    return step2


def test_full_oidc_login_provisions_analyst(client, provider_keys, monkeypatch, fake_provider):
    _run_full_oidc_login(client, provider_keys, monkeypatch)
    # The provisioned account now exists and the session token works.
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "jdoe"
    assert me.json()["user"]["role"] == "analyst"


def test_full_oidc_login_admin_via_group(client, provider_keys, monkeypatch, fake_provider):
    _run_full_oidc_login(client, provider_keys, monkeypatch, group="Domain Admins")
    me = client.get("/api/auth/me")
    assert me.json()["user"]["role"] == "admin"
