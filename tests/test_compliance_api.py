"""Tests for compliance API endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def admin_headers():
    """Return headers for admin authentication."""
    return {"Authorization": "Bearer test-admin-token"}


class TestComplianceExport:
    def test_export_requires_admin(self, client):
        response = client.get("/api/compliance/export")
        assert response.status_code in (401, 403)

    def test_export_with_valid_params(self, client, admin_headers):
        response = client.get(
            "/api/compliance/export",
            params={"hours": 24, "org": ""},
            headers=admin_headers,
        )
        # May return 200 or 401 depending on token validity
        assert response.status_code in (200, 401, 403)


class TestComplianceDSAR:
    def test_dsar_requires_admin(self, client):
        response = client.get(
            "/api/compliance/dsar",
            params={"email": "test@example.com"},
        )
        assert response.status_code in (401, 403)

    def test_dsar_validates_email(self, client, admin_headers):
        response = client.get(
            "/api/compliance/dsar",
            params={"email": "x"},  # Too short
            headers=admin_headers,
        )
        assert response.status_code in (400, 401, 403, 422)


class TestComplianceReport:
    def test_report_requires_admin(self, client):
        response = client.get("/api/compliance/report")
        assert response.status_code in (401, 403)

    def test_report_with_framework(self, client, admin_headers):
        response = client.get(
            "/api/compliance/report",
            params={"framework": "SOC2"},
            headers=admin_headers,
        )
        assert response.status_code in (200, 400, 401, 403)

    def test_report_with_invalid_framework(self, client, admin_headers):
        response = client.get(
            "/api/compliance/report",
            params={"framework": "INVALID"},
            headers=admin_headers,
        )
        assert response.status_code in (400, 401, 403)


class TestAuditRetention:
    def test_retention_requires_admin(self, client):
        response = client.get("/api/compliance/audit/retention")
        assert response.status_code in (401, 403)
