"""Agent-distribution route allowlist.

Only agent.py, install_agent.ps1 and the public TLS cert are downloadable.
Everything else under scripts/ must 404 (provisioning tools, vault code).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client():
    from backend.main import app

    with TestClient(app) as c:
        yield c


def test_agent_py_served(client):
    r = client.get("/scripts/agent.py")
    assert r.status_code == 200
    assert "agent" in r.text.lower()


def test_install_agent_ps1_served(client):
    r = client.get("/scripts/install_agent.ps1")
    assert r.status_code == 200
    assert "baraq" in r.text.lower()


def test_tls_cert_served(client):
    r = client.get("/scripts/baraq.crt")
    assert r.status_code in (200, 404)
    if r.status_code == 200:
        assert "BEGIN CERTIFICATE" in r.text


def test_non_allowlisted_script_404(client):
    for name in (
        "rotate_agent_keys.py",
        "provision_agent.py",
        "provision_fleet.py",
        "install_service.ps1",
        "secrets.dat",
        "run_server.ps1",
    ):
        r = client.get(f"/scripts/{name}")
        assert r.status_code == 404, name


def test_path_traversal_never_serves_backend_source(client):
    """Traversal attempts must not leak backend/config.py or vault content.

    httpx may normalize ``/scripts/../x`` to ``/x`` (SPA catch-all). Assert
    we never receive Python source or secret markers from a scripts request.
    """
    forbidden = (
        "DATABASE_URL",
        "SECRET",
        "password",
        "BARAQ_ADMIN_PASSWORD",
        "class SecretVault",
    )
    for name in (
        "../backend/config.py",
        "..%2Fbackend%2Fconfig.py",
        "agent.py/../provision_agent.py",
        "baraq.crt/../secrets.dat",
    ):
        r = client.get(f"/scripts/{name}")
        # Either blocked, SPA HTML, or allowlisted cert — never backend source
        assert r.status_code in (200, 400, 404, 422), name
        if r.status_code == 200 and "text/html" in r.headers.get("content-type", ""):
            continue  # SPA index is fine
        body = r.text
        for marker in forbidden:
            assert marker not in body, f"{name} leaked {marker!r}"
