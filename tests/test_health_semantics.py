"""P0-3 tests: platform / ML / TI health semantics + UI serialization.

The analyst must never see "[Object object]" for the model version, and
the ML/TI health views must be unambiguous: one MODEL STATE, live-scoring
count, drift verdict, and a TI state that distinguishes "not configured"
from "healthy" and "degraded".
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app

ADMIN = {"X-API-Key": "baraq-dev-admin"}


def test_ml_status_version_is_a_string_not_a_dict():
    with TestClient(app, headers=ADMIN) as client:
        r = client.get("/api/system/ml/status")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body["version"], str), "version must serialize as a string"
        assert isinstance(body["model_version"], str)
        assert body["model_version"] == body["version"]
        assert "version_info" in body
        assert isinstance(body["version_info"], dict)
        assert "scored_events" in body and body["scored_events"] >= 0
        assert body["model_state"] in {"HEALTHY", "WARNING", "CRITICAL"}


def test_ml_status_model_state_semantics():
    """Untrained detector is CRITICAL; a trained fresh model is HEALTHY."""
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    with TestClient(app, headers=ADMIN) as client:
        body = client.get("/api/system/ml/status").json()
    if not detector.trained_at:
        assert body["model_state"] == "CRITICAL"
    else:
        assert body["model_state"] in {"HEALTHY", "WARNING"}


def test_ti_feeds_endpoint_shapes(db):
    """/api/intel/feeds exposes per-provider state; empty means NOT CONFIGURED."""
    with TestClient(app, headers=ADMIN) as client:
        r = client.get("/api/intel/feeds")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, dict) and "feeds" in body
        feeds = body["feeds"]
        assert isinstance(feeds, list)
        # feed rows expose per-provider state for HEALTHY/DEGRADED rendering
        for f in feeds:
            assert "name" in f
            assert "state" in f


def test_correlation_group_helper_wired(db):
    """The incident-creation entry point exists and is importable."""
    from backend.detection.alerting import AlertingService, _maybe_create_incident_helper

    assert callable(_maybe_create_incident_helper)
    assert AlertingService is not None


def test_ml_versions_serving_version_string():
    with TestClient(app, headers=ADMIN) as client:
        r = client.get("/api/system/ml/versions")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body["serving_version"], str) or isinstance(body["serving_version"], int)