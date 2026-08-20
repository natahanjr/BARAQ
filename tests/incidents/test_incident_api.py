"""Phase 7 incident API tests (spec 7.30-7.33, 7.35, 7.39, 7.48, 7.49)."""
from __future__ import annotations

from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.main import app
from backend.incidents import engine
from backend.incidents.contract import INCIDENT_STATES

client = TestClient(app)
API = "/api/incidents-v2"
EVAL_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def _group(group_id, hosts, techniques, severity="high", alert_count=10):
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "destination_ips": [],
        "techniques": techniques,
        "tactics": [],
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
        "external_source": False,
    }


def _finding(finding_id, hosts):
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": "MULTI_STAGE",
        "hosts": hosts,
        "users": [],
        "source_ips": [],
        "member_group_ids": [],
        "confidence": 0.9,
        "first_seen": EVAL_T0,
        "last_seen": EVAL_T0,
    }


def _headers():
    return {"Authorization": "Bearer baraq-dev-admin"}


def _seed(db):
    return engine.create_incident(
        db,
        groups=[
            _group("g-api-001", ["h-api-001"], ["T1021.001"]),
            _group("g-api-002", ["h-api-001"], ["T1059.001"]),
        ],
        findings=[_finding("CF-api-001", ["h-api-001"])],
        now="2026-08-18T10:00:00",
    )


def test_list_incidents(db):
    _seed(db)
    db.commit()
    resp = client.get(f"{API}?primary_entity_type=HOST", headers=_headers())
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1


def test_incident_detail(db):
    res = _seed(db)
    db.commit()
    resp = client.get(f"{API}/{res['incident_id']}", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_id"] == res["incident_id"]
    assert "related_objects" in body


def test_incident_timeline(db):
    res = _seed(db)
    db.commit()
    resp = client.get(f"{API}/{res['incident_id']}/timeline", headers=_headers())
    assert resp.status_code == 200
    assert len(resp.json()["timeline"]) >= 1


def test_incident_graph(db):
    res = _seed(db)
    db.commit()
    resp = client.get(f"{API}/{res['incident_id']}/graph", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["incident_id"] == res["incident_id"]
    assert len(body["edges"]) >= 1


def test_health_endpoint(db):
    _seed(db)
    db.commit()
    resp = client.get(f"{API}/metrics/health", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert "incident_calculations" in body
    assert "active_incidents" in body
    assert "model_version" in body


def test_metrics_never_fabricates_accuracy(db):
    _seed(db)
    db.commit()
    resp = client.get(f"{API}/metrics", headers=_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert "accuracy" not in body
    assert "precision" not in body
    assert "recall" not in body


