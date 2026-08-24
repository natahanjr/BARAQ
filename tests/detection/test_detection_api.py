"""Detection API tests (Phase 2)."""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app


def client():
    return TestClient(app, headers={"X-API-Key": "baraq-dev-admin"})


def test_detectors_list_and_detail():
    with client() as c:
        listing = c.get("/api/detections/detectors")
        assert listing.status_code == 200
        body = listing.json()
        assert body["status"] == "ok"
        ids = [d["detector_id"] for d in body["detectors"]]
        assert ids == ["D001", "D002", "D003", "D004", "D005"]

        detail = c.get("/api/detections/detectors/D003")
        assert detail.json()["detector"]["version"] == "1.0.0"

        unknown = c.get("/api/detections/detectors/D999")
        assert unknown.json()["status"] == "error"


def test_evaluate_endpoint_persists_detection(db):
    record = {
        "timestamp": "2026-08-17T12:00:00+00:00",
        "source": "windows-security",
        "host": "workstation-42",
        "user": "alice",
        "action": "logon",
        "facts": {"logon_type": 10},
        "network": {"src_ip": "203.0.113.5"},
    }
    with client() as c:
        r = c.post("/api/detections/evaluate", json={"records": [record]})
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert len(body["detections"]) == 1
        detection = body["detections"][0]
        assert detection["detector_id"] == "D001"
        assert detection["severity"] == "high"
        assert detection["status"] == "new"
        assert detection["detection_id"].startswith("D001-")

        listing = c.get("/api/detections")
        assert listing.json()["total"] == 1
        assert listing.json()["items"][0]["detection_id"] == detection["detection_id"]

        detail = c.get(f"/api/detections/{detection['detection_id']}")
        assert detail.json()["detection"]["detector_id"] == "D001"
        assert "Why detected" in detail.json()["explain"]
        assert "External Remote RDP Logon" in detail.json()["explain"]

        unknown = c.get("/api/detections/D001-zzzzzzzzzzzz")
        assert unknown.json()["status"] == "error"


def test_evaluate_replay_is_idempotent(db):
    record = {
        "timestamp": "2026-08-17T12:00:00+00:00",
        "source": "windows-security",
        "host": "workstation-42",
        "user": "alice",
        "action": "logon",
        "facts": {"logon_type": 10},
        "network": {"src_ip": "203.0.113.5"},
    }
    with client() as c:
        first = c.post("/api/detections/evaluate", json={"records": [record]})
        second = c.post("/api/detections/evaluate", json={"records": [record]})
        assert len(first.json()["detections"]) == 1
        assert len(second.json()["detections"]) == 1
        assert (
            first.json()["detections"][0]["detection_id"]
            == second.json()["detections"][0]["detection_id"]
        )
        assert c.get("/api/detections").json()["total"] == 1
        assert "explain" in first.json()["detections"][0]


def test_evaluate_benign_record_no_detection(db):
    record = {
        "timestamp": "2026-08-17T12:00:00+00:00",
        "source": "windows-security",
        "host": "workstation-42",
        "user": "alice",
        "action": "logon",
        "facts": {"logon_type": 2},
        "network": {"src_ip": "10.0.0.5"},
    }
    with client() as c:
        r = c.post("/api/detections/evaluate", json={"records": [record]})
        assert r.json() == {"status": "ok", "detections": []}


def test_evaluate_rejects_non_list(db):
    with client() as c:
        r = c.post("/api/detections/evaluate", json={"records": "nope"})
        assert r.json()["status"] == "error"


def test_evaluate_never_touches_v1_state(db):
    from sqlalchemy import text

    tables = ("alerts", "incidents", "entity_risk")
    record = {
        "timestamp": "2026-08-17T12:00:00+00:00",
        "source": "windows-security",
        "host": "workstation-42",
        "user": "alice",
        "action": "logon",
        "facts": {"logon_type": 10},
        "network": {"src_ip": "203.0.113.5"},
    }
    with client() as c:
        before = {t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in tables}
        c.post("/api/detections/evaluate", json={"records": [record]})
        after = {t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in tables}
        assert after == before


def test_api_requires_auth():
    with TestClient(app) as bare:
        assert bare.get("/api/detections").status_code == 401
        assert bare.get("/api/detections/detectors").status_code == 401


def test_list_detections_filters(db):
    from backend.detection.contract import DETECTION
    from backend.detection.engine import persist

    from tests.detection.helpers import event

    finding = DETECTION(
        detector_id="D003",
        detector_version="1.0.0",
        event_id="x",
        event_ids=("x",),
        timestamp=event().timestamp,
        first_seen=event().timestamp,
        last_seen=event().timestamp,
        event_type="process",
        host_name="ws",
        username="u",
        title="Suspicious PowerShell",
        severity="medium",
        confidence=0.7,
        mitre_technique="T1059.001",
    )
    persist(db, finding)
    with client() as c:
        all_items = c.get("/api/detections").json()["items"]
        assert all_items[0]["detector_id"] == "D003"
        filtered = c.get("/api/detections", params={"detector_id": "D001"}).json()
        assert filtered["total"] == 0
        filtered = c.get("/api/detections", params={"severity": "medium"}).json()
        assert filtered["total"] == 1
        filtered = c.get("/api/detections", params={"status": "new"}).json()
        assert filtered["total"] == 1