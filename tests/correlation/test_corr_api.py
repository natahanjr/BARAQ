"""Phase 5 API tests (spec 5.52-5.58, 5.61, 5.62)."""

from fastapi.testclient import TestClient

from backend import config
from backend.api import correlations
from backend.correlation.engine import correlate
from backend.main import app
from tests.correlation.helpers import (
    CORR_T0,
    canonical_specs,
    make_groups,
    stored_correlations,
)

API = "/api/correlations"


def client() -> TestClient:
    return TestClient(app, headers={"Authorization": "Bearer baraq-dev-admin"})


def _seed(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    return stored_correlations(db)[0]


def test_auth_required():
    with TestClient(app) as c:
        assert c.get(API).status_code == 401


def test_list_correlations(db):
    _seed(db)
    with client() as c:
        resp = c.get(API)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["correlations"][0]["correlation_type"] == "LATERAL_MOVEMENT"


def test_list_filters(db):
    _seed(db)
    with client() as c:
        assert c.get(API, params={"status": "ACTIVE"}).json()["total"] == 1
        assert c.get(API, params={"status": "CLOSED"}).json()["total"] == 0
        assert (
            c.get(API, params={"correlation_type": "LATERAL_MOVEMENT"}).json()["total"]
            == 1
        )
        assert (
            c.get(API, params={"correlation_type": "MULTI_STAGE"}).json()["total"] == 0
        )
        assert c.get(API, params={"host": "10.0.0.7"}).json()["total"] == 1
        assert c.get(API, params={"user": "u-r1"}).json()["total"] == 1
        assert c.get(API, params={"source_ip": "198.51.100.9"}).json()["total"] == 1
        assert c.get(API, params={"destination_ip": "10.0.0.7"}).json()["total"] == 1
        assert c.get(API, params={"technique": "T1110"}).json()["total"] == 1
        assert c.get(API, params={"confidence_min": 0.9}).json()["total"] == 0
        assert c.get(API, params={"member_count_min": 5}).json()["total"] == 1
        assert c.get(API, params={"rule_id": "R005"}).json()["total"] == 1
        assert c.get(API, params={"rule_id": "R404"}).json()["total"] == 0
        assert c.get(API, params={"status": "bogus"}).status_code == 422
        assert c.get(API, params={"correlation_type": "bogus"}).status_code == 422


def test_detail_includes_edges(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001").json()
        assert body["correlation"]["correlation_id"] == "CF-000001"
        assert body["correlation"]["confidence"] == 0.88
        edge_types = {e["relationship_type"] for e in body["edges"]}
        assert "LATERAL_MOVEMENT" in edge_types


def test_unknown_detail_404(db):
    with client() as c:
        assert c.get(f"{API}/CF-999999").status_code == 404


def test_member_groups_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/groups").json()
        assert body["total"] == 5
        assert body["members"][0]["membership_reason"]
        assert body["members"][0]["role"] == "seed"


def test_member_alerts_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/alerts").json()
        assert body["total"] == 30


def test_evidence_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/evidence").json()
        assert body["total"] > 0
        assert body["evidence"][0]["reason"]


def test_timeline_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/timeline").json()
        assert len(body["timeline"]) == 5
        assert body["timeline"][0]["behavior_group_id"]


def test_graph_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/graph").json()
        assert len(body["nodes"]) == 5
        assert len(body["edges"]) >= 10


def test_audit_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/CF-000001/audit").json()
        actions = {e["action"] for e in body["events"]}
        assert "CORRELATION_CREATED" in actions
        assert "EDGE_CREATED" in actions
        assert "GROUP_ADDED" in actions


def test_metrics_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/metrics").json()
        assert body["total_findings"] == 1
        assert body["rule_distribution"]["R005"] == 1
        assert body["median_groups_per_finding"] == 5.0
        assert body["sample_size_findings"] == 1


def test_evaluation_endpoint(db):
    with client() as c:
        body = c.get(f"{API}/evaluation").json()
        assert "true_positives" in body
        assert "false_positives" in body
        assert "true_negatives" in body
        assert "false_negatives" in body
        assert body["labeled_chains"] >= 3


def test_rules_registry_endpoint(db):
    with client() as c:
        body = c.get(f"{API}/rules").json()
        assert body["version"] == "1.0.0"
        assert len(body["rules"]) == 9
        assert body["rules"][0]["rule_id"] == "R001"


def test_gate_disabled_returns_404(monkeypatch):
    monkeypatch.setattr(config, "CORRELATION_ENABLED", False)
    with client() as c:
        assert c.get(API).status_code == 404
        assert c.get(f"{API}/metrics").status_code == 404


def test_pep_562_gate_exposed():
    assert correlations.CORRELATION_ENABLED is config.CORRELATION_ENABLED
