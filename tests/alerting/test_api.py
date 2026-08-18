"""Alert API tests (spec 3.20-3.24, 3.41)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend.alerting.engine import process_detection
from backend.main import app

from tests.alerting.helpers import T0, detection

API = "/api/alerts-v2"


def client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


def _seed(db, **kw):
    return process_detection(db, detection(**kw), now=T0)


def test_requires_auth(db):
    with TestClient(app) as c:
        r = c.get(API)
        assert r.status_code == 401


def test_list_empty_when_no_alerts(db):
    with client() as c:
        body = c.get(API).json()
        assert body["status"] == "ok"
        assert body["items"] == []


def test_list_and_detail(db):
    alert = _seed(db, host="ml-host", user="ml-online-user", source_ip="185.0.0.1")
    with client() as c:
        listing = c.get(API).json()
        assert listing["total"] == 1
        item = listing["items"][0]
        assert item["alert_id"] == alert.alert_id
        assert item["severity"] == "high"
        assert item["occurrence_count"] == 1
        assert "age_seconds" in item
        detail = c.get(f"{API}/{alert.alert_id}").json()
        assert detail["alert"]["title"] == alert.title
        assert any(e["action"] == "CREATED" for e in detail["audit"])


def test_list_filters(db):
    _seed(db, host="ml-host", severity="high")
    _seed(
        db,
        detector_id="D002", mitre="T1110", host="finance-host", severity="medium",
    )
    with client() as c:
        assert c.get(API, params={"severity": "high"}).json()["total"] == 1
        assert c.get(API, params={"host": "finance-host"}).json()["total"] == 1
        assert c.get(API, params={"mitre": "T1110"}).json()["total"] == 1
        assert c.get(API, params={"status": "OPEN"}).json()["total"] == 2
        assert c.get(API, params={"severity": "critical"}).json()["total"] == 0
        assert c.get(API, params={"severity": "bogus"}).status_code == 422
        assert c.get(API, params={"status": "bogus"}).status_code == 422


def test_acknowledge_sets_timestamps_and_audit(db):
    alert = _seed(db)
    with client() as c:
        body = c.post(f"{API}/{alert.alert_id}/acknowledge").json()
        assert body["alert"]["status"] == "ACKNOWLEDGED"
        assert body["alert"]["acknowledged_at"] is not None
        assert body["alert"]["acknowledged_by"] is not None
        detail = c.get(f"{API}/{alert.alert_id}").json()
        actions = [e["action"] for e in detail["audit"]]
        assert actions == ["CREATED", "ACKNOWLEDGED"]


def test_assign_validates_server_side(db):
    alert = _seed(db)
    with client() as c:
        r = c.post(f"{API}/{alert.alert_id}/assign", json={})
        assert r.status_code == 422
        body = c.post(
            f"{API}/{alert.alert_id}/assign", json={"assigned_to": "analyst@example"}
        ).json()
        assert body["alert"]["assigned_to"] == "analyst@example"
        assert body["alert"]["assigned_at"] is not None


def test_resolve_close_reopen_flow(db):
    alert = _seed(db)
    with client() as c:
        c.post(f"{API}/{alert.alert_id}/in-progress")
        body = c.post(f"{API}/{alert.alert_id}/resolve").json()
        assert body["alert"]["status"] == "RESOLVED"
        assert body["alert"]["resolved_at"] is not None
        body = c.post(f"{API}/{alert.alert_id}/close").json()
        assert body["alert"]["status"] == "CLOSED"
        r = c.post(f"{API}/{alert.alert_id}/close")
        assert r.status_code == 409
        body = c.post(f"{API}/{alert.alert_id}/reopen").json()
        assert body["alert"]["status"] == "OPEN"


def test_illegal_transition_rejected(db):
    alert = _seed(db)
    with client() as c:
        r = c.post(f"{API}/{alert.alert_id}/close")
        assert r.status_code == 409
        r = c.post(f"{API}/{alert.alert_id}/reopen")
        assert r.status_code == 409  # OPEN -> OPEN is not a reopen path


def test_occurrences_and_evidence_endpoints(db):
    alert = _seed(db)
    process_detection(db, detection(minutes_ago=0.1), now=T0)
    with client() as c:
        occ = c.get(f"{API}/{alert.alert_id}/occurrences").json()
        assert len(occ["items"]) == 2
        assert occ["items"][0]["evidence"][0]["field"] == "logon_type"
        evidence = c.get(f"{API}/{alert.alert_id}/evidence").json()
        assert len(evidence["evidence"]) == 2


def test_feedback_endpoint_records_everything(db):
    alert = _seed(db)
    with client() as c:
        r = c.post(f"{API}/{alert.alert_id}/feedback", json={"feedback_type": "MAYBE"})
        assert r.status_code == 422
        body = c.post(
            f"{API}/{alert.alert_id}/feedback",
            json={"feedback_type": "false_positive", "comment": "scan box"},
        ).json()
        assert body["feedback"]["feedback_type"] == "FALSE_POSITIVE"
        assert body["feedback"]["comment"] == "scan box"
        assert body["feedback"]["analyst"]
        stats = c.get(f"{API}/feedback-stats").json()
        assert stats["stats"]["false_positives"] == 1
        assert stats["stats"]["false_positive_rate"] is None  # tiny sample


def test_metrics_endpoint(db):
    _seed(db)
    process_detection(db, detection(minutes_ago=0.1), now=T0)
    with client() as c:
        body = c.get(f"{API}/metrics").json()
        m = body["metrics"]
        assert m["total_alerts"] == 1
        assert m["occurrence_count"] == 2
        assert m["deduplicated_alerts"] == 1
        assert m["age_buckets"]["0-15m"] == 1


def test_suppression_endpoints(db):
    with client() as c:
        r = c.post(f"{API}/suppressions", json={"reason": "maint"})
        assert r.status_code == 422
        r = c.post(
            f"{API}/suppressions",
            json={
                "reason": "approved maintenance",
                "expires_at": (T0 + timedelta(hours=2)).isoformat(),
                "scope": {"detector_id": "D001", "host": "ml-host"},
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["rule"]["policy_id"]
        listed = c.get(f"{API}/suppressions").json()
        assert listed["total"] if "total" in listed else listed["items"]
        assert listed["items"][0]["reason"] == "approved maintenance"


def test_suppressed_detection_no_visible_alert(db):
    from backend.alerting.suppression import create_rule

    create_rule(db, policy_id="SUP-1", reason="approved maintenance",
                expires_at=T0 + timedelta(hours=2),
                scope={"detector_id": "D001", "host": "workstation-42"})
    db.commit()
    alert = process_detection(db, detection(), now=T0)
    assert alert is None
    with client() as c:
        assert c.get(API).json()["items"] == []


def test_unknown_alert_404(db):
    with client() as c:
        assert c.get(f"{API}/ALR-999999").status_code == 404
        assert c.post(f"{API}/ALR-999999/acknowledge").status_code == 404


def test_gate_disables_api(monkeypatch, db):
    import backend.config as config

    monkeypatch.setattr(config, "ALERTS_V2_ENABLED", False)
    _seed(db)
    with client() as c:
        body = c.get(API).json()
        assert body["status"] == "disabled"
        assert c.get(f"{API}/metrics").json()["status"] == "disabled"