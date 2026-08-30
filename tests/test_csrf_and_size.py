"""SC6 hardening tests: CSRF double-submit protection for cookie sessions and
request body size limits (413).

The session cookie path is exercised with a bare TestClient (no API key, no
Authorization header) exactly like a browser that only has the httpOnly
session cookie. Bearer/API-key callers must remain unaffected by CSRF.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.database.connection import SessionLocal
from backend.database.models import User


@pytest.fixture(scope="module")
def app():
    from backend.main import app

    return app


@pytest.fixture()
def seeded_admin():
    from backend.auth import hash_password

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


@pytest.fixture()
def cookie_browser(app, seeded_admin):
    """A client that logs in with the real login form and keeps ONLY the
    session cookie (browser semantics: no API key, no Authorization header)."""
    with TestClient(app) as client:
        resp = client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "baraqadmin",
            },
        )
        assert resp.status_code == 200, resp.text
        yield client


def _post(client, path, json_body=None):
    return client.post(path, json=json_body or {})


def test_login_sets_csrf_cookie(cookie_browser):
    cookies = cookie_browser.cookies
    assert "baraq_csrf" in cookies
    assert "baraq_session" in cookies


def test_cookie_state_change_without_token_rejected(cookie_browser):
    resp = _post(cookie_browser, "/api/system/collect")
    assert resp.status_code == 403
    assert "CSRF" in resp.json().get("detail", "")


def test_cookie_state_change_with_valid_token_allowed(cookie_browser):
    csrf = cookie_browser.cookies["baraq_csrf"]
    resp = cookie_browser.post(
        "/api/system/collect",
        headers={"X-CSRF-Token": csrf},
    )
    assert resp.status_code in (200, 201, 202), resp.text


def test_cookie_state_change_with_wrong_token_rejected(cookie_browser):
    resp = cookie_browser.post(
        "/api/system/collect",
        headers={"X-CSRF-Token": "attacker-controlled-value"},
    )
    assert resp.status_code == 403


def test_cookie_get_requests_not_checked(cookie_browser):
    # Reads are CSRF-immune (no state change) and must pass with only the cookie.
    resp = cookie_browser.get("/api/system/status")
    assert resp.status_code == 200, resp.text


def test_bearer_caller_skips_csrf(app, seeded_admin):
    """API callers with an explicit Authorization header cannot be CSRF'd."""
    from backend.auth import create_token

    token = create_token(1, "admin", "admin")
    with TestClient(app) as client:
        resp = client.post(
            "/api/system/collect",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code in (200, 201, 202), resp.text


def test_api_key_caller_skips_csrf(app):
    with TestClient(app) as client:
        resp = client.post(
            "/api/system/collect",
            headers={"X-API-Key": "baraq-dev-admin"},
        )
        assert resp.status_code in (200, 201, 202), resp.text


def test_public_login_no_csrf_needed(app, seeded_admin):
    """Pre-auth endpoints (login) must not demand a CSRF token."""
    with TestClient(app) as client:
        resp = client.post(
            "/api/auth/login",
            json={
                "username": "admin",
                "password": "baraqadmin",
            },
        )
        assert resp.status_code == 200, resp.text


def test_csrf_cookie_reissued_on_relogin(cookie_browser):
    first = cookie_browser.cookies["baraq_csrf"]
    resp = cookie_browser.post(
        "/api/auth/login",
        json={
            "username": "admin",
            "password": "baraqadmin",
        },
    )
    assert resp.status_code == 200
    assert cookie_browser.cookies["baraq_csrf"] != first


# ---------------------------------------------------------------------------
# Request body size limits
# ---------------------------------------------------------------------------


def test_content_length_over_limit_rejected(app, seeded_admin, monkeypatch):
    import backend.config as cfg

    monkeypatch.setattr(cfg, "MAX_REQUEST_BYTES", 1024)
    with TestClient(app) as client:
        # The assistant chat endpoint accepts text; a huge body must 413
        # before any handler (or pydantic) runs.
        big = {"message": "x" * 5000}
        resp = client.post(
            "/api/assistant/chat",
            json=big,
            headers={"X-API-Key": "baraq-dev-admin"},
        )
        assert resp.status_code == 413, resp.text


def test_content_length_within_limit_allowed(cookie_browser):
    resp = cookie_browser.post(
        "/api/assistant/chat",
        json={"message": "hello"},
        headers={"X-CSRF-Token": cookie_browser.cookies["baraq_csrf"]},
    )
    assert resp.status_code == 200, resp.text
