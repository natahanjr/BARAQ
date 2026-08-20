"""Phase 6 API tests (spec 6.46-6.48, 6.53, 6.65, 6.77)."""
from __future__ import annotations

import pytest
import backend.config as config
from fastapi.testclient import TestClient

from backend.api import risk as risk_api
from backend.risk import engine
from backend.main import app

from tests.risk.helpers import (
    RISK_T0,
    alert_evidence,
    finding_evidence,
    group_evidence,
)

API = "/api/risk"


def client() -> TestClient:
    return TestClient(app, headers={"Authorization": "Bearer baraq-dev-admin"})


def _seed(db):
    engine.apply_group(
        db, group_evidence("g5", "h1", ["T1021.001"], alert_count=10),
        now=RISK_T0,
    )
    engine.apply_group(
        db, group_evidence("g4", "h-src", ["T1110"], user="u1"),
        now=RISK_T0,
    )
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=RISK_T0)
    db.commit()
    return engine.risk_for_entity(db, "HOST", "h1")


def test_auth_required():
    with TestClient(app) as c:
        assert c.get(API).status_code == 401


def test_list_risks(db):
    _seed(db)
    with client() as c:
        body = c.get(API).json()
        assert body["count"] == 5  # h1, h-src, u-eval, u1, 203.0.113.5
        payload = body["risks"][0]
        for field in (
            "risk_id", "entity_type", "entity_id", "entity_name", "score",
            "severity", "state", "confidence", "trend", "first_seen",
            "last_seen", "active_factor_count", "evidence_count",
            "alert_count", "group_count", "correlation_count",
            "created_at", "updated_at", "last_calculated_at",
        ):
            assert field in payload


def test_list_filters(db):
    _seed(db)
    with client() as c:
        # h1 52 MEDIUM/HIGH, h-src 38 LOW/ELEVATED, u-eval 28 LOW/ELEVATED,
        # u1 18 MINIMAL/NORMAL, 203.0.113.5 38 LOW/ELEVATED (RF010 x2 groups).
        assert c.get(API, params={"entity_type": "HOST"}).json()["count"] == 2
        assert c.get(API, params={"entity_type": "USER"}).json()["count"] == 2
        assert c.get(API, params={"severity": "MEDIUM"}).json()["count"] == 1
        assert c.get(API, params={"severity": "LOW"}).json()["count"] == 3
        assert c.get(API, params={"severity": "MINIMAL"}).json()["count"] == 1
        assert c.get(API, params={"state": "HIGH"}).json()["count"] == 1
        assert c.get(API, params={"state": "ELEVATED"}).json()["count"] == 3
        assert c.get(API, params={"state": "NORMAL"}).json()["count"] == 1
        assert c.get(API, params={"trend": "RISING"}).json()["count"] == 3
        assert c.get(API, params={"trend": "UNKNOWN"}).json()["count"] == 2
        assert c.get(API, params={"score_min": 50}).json()["count"] == 1
        assert c.get(API, params={"score_max": 20}).json()["count"] == 1
        assert c.get(API, params={"factor_type": "LATERAL_MOVEMENT"}).json()["count"] == 1
        assert c.get(API, params={"source_type": "correlation_finding"}).json()["count"] == 3
        assert c.get(API, params={"entity_id": "h1"}).json()["count"] == 1
        assert c.get(API, params={"entity_type": "GADGET"}).status_code == 422
        assert c.get(API, params={"severity": "bogus"}).status_code == 422
        assert c.get(API, params={"state": "bogus"}).status_code == 422
        assert c.get(API, params={"trend": "bogus"}).status_code == 422


def test_risk_detail(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}").json()
        assert body["risk_id"] == risk.risk_id
        assert body["entity_type"] == "HOST"
        assert c.get(f"{API}/ER-999999").status_code == 404


def test_entity_lookup(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/entity/HOST/h1").json()
        assert body["risk_id"] == risk.risk_id
        assert c.get(f"{API}/entity/HOST/nope").status_code == 404
        assert c.get(f"{API}/entity/GADGET/h1").status_code == 422


def test_factors_endpoint(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}/factors").json()
        assert body["count"] >= 4
        for factor in body["factors"]:
            assert factor["factor_id"]
            assert factor["reason"]
            assert factor["evidence"] is not None
            assert factor["created_at"]


def test_explain_endpoint_decomposes_score(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}/explain").json()
        assert body["risk_id"] == risk.risk_id
        assert body["score"] == risk.score
        assert body["severity"] == risk.severity
        total = sum(c["contribution"] for c in body["factor_contributions"])
        assert total == body["score"]
        assert body["risk_model_version"] == "1.0.0"
        for contribution in body["factor_contributions"]:
            assert contribution["reason"]
            assert contribution["source_id"]


def test_timeline_endpoint(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}/timeline").json()
        assert body["count"] >= 2
        assert body["timeline"][-1]["score"] == risk.score
        for point in body["timeline"]:
            assert point["captured_at"]
            assert point["risk_model_version"] == "1.0.0"


def test_graph_endpoint(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}/graph").json()
        assert body["nodes"][0]["id"] == risk.risk_id
        assert len(body["edges"]) >= 4
        for edge in body["edges"]:
            assert edge["factor_id"]
            assert edge["origin"] in ("DIRECT", "CONTEXTUAL")


def test_audit_endpoint(db):
    risk = _seed(db)
    with client() as c:
        body = c.get(f"{API}/{risk.risk_id}/audit").json()
        actions = {event["action"] for event in body["events"]}
        assert "RISK_CREATED" in actions
        assert "FACTOR_ADDED" in actions
        assert "RISK_RECALCULATED" in actions


def test_recalculate_endpoint(db):
    risk = _seed(db)
    with client() as c:
        body = c.post(f"{API}/recalculate/{risk.risk_id}").json()
        # Recalculation happens "now": stored factors decay, so the score
        # must equal an engine-side recalculation at the same moment.
        recomputed = engine.manual_recalculate(db, risk.risk_id)
        assert body["score"] == pytest.approx(recomputed["score"], abs=0.001)
        assert body["severity"] == recomputed["severity"]
        assert c.post(f"{API}/recalculate/ER-999999").status_code == 404


def test_ranking_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/ranking/top", params={"kind": "hosts"}).json()
        assert body["kind"] == "hosts"
        assert body["entities"][0]["entity_id"] == "h1"
        assert c.get(f"{API}/ranking/top", params={"kind": "users"}).status_code == 200
        assert c.get(f"{API}/ranking/top", params={"kind": "bogus"}).status_code == 422


def test_metrics_endpoint(db):
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/metrics").json()
        assert body["total_entities"] >= 3
        assert body["entities_with_risk"] == body["total_entities"]
        assert body["max_score"] > 0
        assert set(body["calculation_latency"]) == {"p50_ms", "p95_ms", "p99_ms", "max_ms"}
        assert body["risk_calculations"] > 0


def test_health_endpoint(db):
    with client() as c:
        body = c.get(f"{API}/metrics/health").json()
        assert body["healthy"] is False
        assert body["total_entities"] == 0
    _seed(db)
    with client() as c:
        body = c.get(f"{API}/metrics/health").json()
        assert body["total_entities"] > 0
        assert body["last_calculation_at"] is not None


def test_factor_registry_endpoint():
    with client() as c:
        body = c.get(f"{API}/factors/registry").json()
        assert body["count"] >= 8
        factor_ids = {f["factor_id"] for f in body["factors"]}
        assert "RF001_EXTERNAL_ACCESS" in factor_ids
        assert "RF008_RECENCY" in factor_ids


def test_gate_returns_404_when_disabled(db, monkeypatch):
    monkeypatch.setattr(risk_api.config, "RISK_ENABLED", False)
    _seed(db)
    with client() as c:
        assert c.get(API).status_code == 404
        assert c.get(f"{API}/metrics").status_code == 404


def test_ingest_evidence_endpoint_absent(db):
    _seed(db)
    with client() as c:
        # Risk is a read-oriented surface: evidence is never POSTed by
        # clients (spec 6.46 read-only design).
        assert c.post(f"{API}/ingest").status_code != 200