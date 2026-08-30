"""Phase 4 API tests (spec 4.31-4.33, 4.41)."""

from fastapi.testclient import TestClient

from backend import config
from backend.aggregation.engine import process_alerts
from backend.api import behavior_groups
from backend.main import app
from tests.aggregation.helpers import (
    GROUP_T0,
    fabricate_alerts,
    stored_groups,
)

API = "/api/behavior-groups"


def client() -> TestClient:
    return TestClient(app, headers={"Authorization": "Bearer baraq-dev-admin"})


def _seed(db):
    alerts = fabricate_alerts(
        db,
        [
            {
                "minutes_ago": 5.0,
                "evidence": [
                    {
                        "field": "logon_type",
                        "value": "10",
                        "reason": "detection evidence",
                    },
                    {
                        "field": "source_ip",
                        "value": "203.0.113.5",
                        "reason": "detection evidence",
                    },
                ],
            },
            {
                "detector_id": "D002",
                "mitre": "T1110",
                "minutes_ago": 4.0,
                "evidence": [
                    {
                        "field": "logon_type",
                        "value": "3",
                        "reason": "detection evidence",
                    },
                    {
                        "field": "source_ip",
                        "value": "203.0.113.5",
                        "reason": "detection evidence",
                    },
                ],
            },
            {
                "detector_id": "D003",
                "host": "finance-host",
                "user": "bob",
                "source_ip": "203.0.113.7",
                "mitre": "T1059.001",
                "minutes_ago": 3.0,
            },
            {
                "detector_id": "D005",
                "host": "backup-host",
                "user": "system",
                "source_ip": "203.0.113.9",
                "mitre": "T1486",
                "minutes_ago": 2.0,
            },
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    return stored_groups(db)


def test_auth_required():
    with TestClient(app) as c:
        assert c.get(API).status_code == 401


def test_list_groups(db):
    _seed(db)
    with client() as c:
        resp = c.get(API)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 3
        assert len(body["behavior_groups"]) == 3


def test_list_filters(db):
    _seed(db)
    with client() as c:
        assert c.get(API, params={"status": "ACTIVE"}).json()["total"] == 3
        assert c.get(API, params={"status": "CLOSED"}).json()["total"] == 0
        assert c.get(API, params={"host": "workstation-42"}).json()["total"] == 1
        assert c.get(API, params={"host": "bogus"}).json()["total"] == 0
        assert c.get(API, params={"user": "bob"}).json()["total"] == 1
        assert c.get(API, params={"source_ip": "203.0.113.5"}).json()["total"] == 1
        assert c.get(API, params={"mitre_technique": "T1059.001"}).json()["total"] == 1
        assert c.get(API, params={"severity": "high"}).json()["total"] == 3
        assert c.get(API, params={"alert_count_min": 2}).json()["total"] == 1
        assert c.get(API, params={"status": "bogus"}).status_code == 422
        assert c.get(API, params={"severity": "bogus"}).status_code == 422


def test_group_detail_and_audit(db):
    groups = _seed(db)
    group_id = groups[0].behavior_group_id
    with client() as c:
        resp = c.get(f"{API}/{group_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["behavior_group"]["behavior_group_id"] == group_id
        assert body["behavior_group"]["alert_count"] == 2
        assert body["behavior_group"]["highest_severity"] == "high"
        assert body["behavior_group"]["title"] == "Remote Authentication Activity"
        actions = [e["action"] for e in body["audit"]]
        assert "GROUP_CREATED" in actions
        assert "ALERT_ADDED" in actions


def test_unknown_group_404(db):
    with client() as c:
        assert c.get(f"{API}/BG-999999").status_code == 404
        assert c.get(f"{API}/BG-999999/alerts").status_code == 404


def test_group_alerts_endpoint(db):
    groups = _seed(db)
    group_id = groups[0].behavior_group_id
    with client() as c:
        resp = c.get(f"{API}/{group_id}/alerts")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert all(a["alert_id"].startswith("ALR-") for a in body["alerts"])


def test_group_evidence_endpoint(db):
    groups = _seed(db)
    group_id = groups[0].behavior_group_id
    with client() as c:
        resp = c.get(f"{API}/{group_id}/evidence")
        assert resp.status_code == 200
        assert resp.json()["total"] == 4  # 2 alerts x 2 evidence items
        fields = {e["field"] for e in resp.json()["evidence"]}
        assert "logon_type" in fields
        assert "source_ip" in fields


def test_group_timeline_is_chronological(db):
    groups = _seed(db)
    group_id = groups[0].behavior_group_id
    with client() as c:
        timeline = c.get(f"{API}/{group_id}/timeline").json()["timeline"]
        assert len(timeline) == 2
        times = [t["time"] for t in timeline]
        assert times == sorted(times)


def test_close_group(db):
    groups = _seed(db)
    group_id = groups[0].behavior_group_id
    with client() as c:
        resp = c.post(f"{API}/{group_id}/close")
        assert resp.status_code == 200
        assert resp.json()["status"] == "CLOSED"
        # Closing twice is illegal (CLOSED -> CLOSED not in the table).
        assert c.post(f"{API}/{group_id}/close").status_code == 409
        assert c.get(API, params={"status": "CLOSED"}).json()["total"] == 1


def test_metrics_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/metrics").json()
        assert body["total_groups"] == 3
        assert body["sample_size_alerts"] == 4
        assert body["group_reduction_ratio"] == 0.25


def test_evaluation_endpoint_raw_counts(db):
    with client() as c:
        body = c.get(f"{API}/evaluation").json()
        assert body["labeled_groups"] >= 8
        assert "accuracy" not in body
        assert (
            body["correct_groupings"] + body["incorrect_groupings"]
            == body["labeled_groups"]
        )


def test_disabled_gate(monkeypatch):
    monkeypatch.setattr(behavior_groups, "BEHAVIOR_GROUPS_ENABLED", False)
    monkeypatch.setattr(config, "BEHAVIOR_GROUPS_ENABLED", False)
    with client() as c:
        assert c.get(API).status_code == 404
