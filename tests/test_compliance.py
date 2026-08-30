"""Compliance (roadmap 3.3): anonymized exports, DSAR, audit retention."""

from __future__ import annotations

from datetime import UTC

import pytest

from backend.database.models import AuditLog, NormalizedEvent


def _add_event(db, user="alice@corp.test"):
    from datetime import datetime

    ev = NormalizedEvent(
        source="test",
        event_id=4625,
        category="logon",
        severity="medium",
        message=f"Failed logon for {user}",
        user=user,
        host="laptop-01",
        timestamp=datetime.now(UTC),
    )
    db.add(ev)
    db.commit()
    return ev.id


def test_anonymize_masks_pii():
    from backend.compliance import anonymize

    out = anonymize(
        {
            "user": "alice",
            "host": "laptop-01",
            "source_ip": "10.0.0.1",
            "message": "logon ok",
            "nested": {"email": "a@b.c"},
        }
    )
    assert out["user"].startswith("anonymized-")
    assert out["user"] != "alice"
    assert out["host"].startswith("anonymized-")
    assert out["source_ip"].startswith("anonymized-")
    assert out["message"] == "logon ok"
    assert out["nested"]["email"].startswith("anonymized-")


def test_anonymized_export_and_dsar(db):
    from backend.compliance import anonymized_export, dsar_package

    _add_event(db)
    data = anonymized_export(db, hours=24)
    assert data["counts"]["events"] >= 1
    assert all(e["user"].startswith("anonymized-") for e in data["events"])

    pkg = dsar_package(db, "alice@corp.test")
    assert pkg["counts"]["events"] >= 1
    assert pkg["events"][0]["user"] == "alice@corp.test"

    with pytest.raises(ValueError):
        dsar_package(db, "")


def test_compliance_report_shape(db):
    from backend.compliance import compliance_report

    report = compliance_report(db)
    assert "inventory" in report
    assert "retention_days" in report
    assert report["retention_days"]["telemetry"] >= 1
    assert report["retention_days"]["audit_trail"] >= 30


def test_audit_retention_purge(db):
    from datetime import datetime, timedelta

    from backend.compliance import purge_old_audit

    old = AuditLog(
        actor="system",
        action="test.old",
        detail="old entry",
        created_at=datetime.now(UTC) - timedelta(days=400),
    )
    recent = AuditLog(
        actor="system",
        action="test.recent",
        detail="recent entry",
        created_at=datetime.now(UTC),
    )
    db.add_all([old, recent])
    db.commit()

    purged = purge_old_audit(db, days=365)
    assert purged == 1
    remaining = db.query(AuditLog).filter(AuditLog.detail == "recent entry").first()
    assert remaining is not None
    assert db.query(AuditLog).filter(AuditLog.detail == "old entry").first() is None


def test_compliance_endpoints_require_admin():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/compliance/export", params={"hours": 1})
        assert r.status_code == 200, r.text
        assert r.json()["counts"]["events"] >= 0

        r2 = client.get("/api/compliance/report")
        assert r2.status_code == 200
        assert "inventory" in r2.json()

        r3 = client.get("/api/compliance/audit/retention")
        assert r3.status_code == 200
        assert "retention_days" in r3.json()

    from backend.main import app as app2

    with TestClient(app2, headers={"X-API-Key": "baraq-dev-analyst"}) as bare:
        r4 = bare.get("/api/compliance/report")
        assert r4.status_code == 403
