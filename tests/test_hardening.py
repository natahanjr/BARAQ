"""API hardening (roadmap 5.3): security headers, rate limiting, IP ACLs."""
from __future__ import annotations

from fastapi.testclient import TestClient


def test_security_headers_present():
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old = cfg.SECURITY_HEADERS
    cfg.SECURITY_HEADERS = True
    main_mod.SECURITY_HEADERS = True
    try:
        with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
            r = client.get("/api/system/status")
            assert r.status_code == 200
            assert r.headers.get("x-content-type-options") == "nosniff"
            assert r.headers.get("x-frame-options") == "DENY"
            assert "frame-ancestors" in r.headers.get("content-security-policy", "")
            assert "strict-transport-security" in r.headers
    finally:
        cfg.SECURITY_HEADERS = old
        main_mod.SECURITY_HEADERS = old


def test_api_csp_is_lockdown():
    """API responses must keep the strictest possible policy."""
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old = cfg.SECURITY_HEADERS
    cfg.SECURITY_HEADERS = True
    main_mod.SECURITY_HEADERS = True
    try:
        with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
            r = client.get("/api/system/status")
            assert r.status_code == 200
            csp = r.headers.get("content-security-policy", "")
            assert "default-src 'none'" in csp
            assert "script-src" not in csp
    finally:
        cfg.SECURITY_HEADERS = old
        main_mod.SECURITY_HEADERS = old


def test_spa_page_csp_allows_bundles():
    """The SPA page must never get 'default-src none' - that blocks the JS/CSS
    bundles and inline bootstrap scripts and renders a black screen.

    Regression: the security-header middleware once applied the API lock-down
    policy to every response, breaking the dashboard (black screen) because
    the browser refused to load /assets/* and the inline scripts.
    """
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old = cfg.SECURITY_HEADERS
    cfg.SECURITY_HEADERS = True
    main_mod.SECURITY_HEADERS = True
    try:
        with TestClient(app) as client:
            r = client.get("/")
            assert r.status_code == 200
            assert "text/html" in r.headers["content-type"]
            csp = r.headers.get("content-security-policy", "")
            assert "default-src 'none'" not in csp
            assert "script-src 'self'" in csp
            assert "style-src 'self'" in csp
            # The SPA entry point must never be cached so the browser always
            # picks up the latest hashed asset references.
            assert r.headers.get("cache-control") == "no-store"
    finally:
        cfg.SECURITY_HEADERS = old
        main_mod.SECURITY_HEADERS = old


def test_spa_assets_served_with_spa_csp():
    """Hashed /assets/* bundles must be reachable under the SPA policy."""
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old = cfg.SECURITY_HEADERS
    cfg.SECURITY_HEADERS = True
    main_mod.SECURITY_HEADERS = True
    try:
        with TestClient(app) as client:
            html = client.get("/").text
            asset = next(
                (m for m in __import__("re").finditer(r'/assets/[^"\']+\.js', html)),
                None,
            )
            assert asset is not None, "index.html should reference a JS bundle"
            r = client.get(asset.group(0))
            assert r.status_code == 200
            csp = r.headers.get("content-security-policy", "")
            assert "default-src 'none'" not in csp
            assert "script-src 'self'" in csp
            assert r.headers.get("cache-control") == "public, max-age=31536000, immutable"
    finally:
        cfg.SECURITY_HEADERS = old
        main_mod.SECURITY_HEADERS = old


def test_rate_limit_returns_429():
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old_limit, old_burst = cfg.API_RATE_LIMIT, cfg.API_RATE_BURST
    cfg.API_RATE_LIMIT, cfg.API_RATE_BURST = 3, 3
    main_mod._rate_buckets.clear()
    try:
        with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
            for _ in range(3):
                r = client.get("/api/system/status")
                assert r.status_code == 200
            r = client.get("/api/system/status")
            assert r.status_code == 429
            assert "Retry-After" in r.headers
    finally:
        cfg.API_RATE_LIMIT, cfg.API_RATE_BURST = old_limit, old_burst
        main_mod._rate_buckets.clear()


def test_rate_limit_bypass_when_disabled():
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old_limit = cfg.API_RATE_LIMIT
    cfg.API_RATE_LIMIT = 0
    main_mod._rate_buckets.clear()
    try:
        with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
            for _ in range(5):
                assert client.get("/api/system/status").status_code == 200
    finally:
        cfg.API_RATE_LIMIT = old_limit
        main_mod._rate_buckets.clear()


def test_ip_whitelist_blocks_unknown_client(monkeypatch):
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    monkeypatch.setattr(cfg, "API_IP_WHITELIST", ["192.0.2.0/24"])
    monkeypatch.setattr(cfg, "API_IP_BLOCKLIST", [])
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/status")
        assert r.status_code == 403
        assert "not permitted" in r.json()["detail"]


def test_ip_blocklist_denies(monkeypatch):
    import backend.config as cfg

    from backend.main import app

    monkeypatch.setattr(cfg, "API_IP_BLOCKLIST", ["127.0.0.0/8"])
    monkeypatch.setattr(cfg, "API_IP_WHITELIST", [])
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/status")
        assert r.status_code == 403


def test_ip_acls_empty_allow_all(monkeypatch):
    import backend.config as cfg

    from backend.main import app

    monkeypatch.setattr(cfg, "API_IP_WHITELIST", [])
    monkeypatch.setattr(cfg, "API_IP_BLOCKLIST", [])
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        assert client.get("/api/system/status").status_code == 200


def test_health_endpoint_skips_rate_limit():
    import backend.config as cfg
    import backend.main as main_mod

    from backend.main import app

    old_limit, old_burst = cfg.API_RATE_LIMIT, cfg.API_RATE_BURST
    cfg.API_RATE_LIMIT, cfg.API_RATE_BURST = 2, 2
    main_mod._rate_buckets.clear()
    try:
        with TestClient(app) as client:
            for _ in range(5):
                assert client.get("/api/health").status_code == 200
    finally:
        cfg.API_RATE_LIMIT, cfg.API_RATE_BURST = old_limit, old_burst
        main_mod._rate_buckets.clear()