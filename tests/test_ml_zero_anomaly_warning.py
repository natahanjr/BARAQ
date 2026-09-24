"""ML zero-anomaly operator warning + rule-only hybrid risk guard.

Fresh deployments never flag ML anomalies until enough real telemetry
trains (ML_TRAIN_MIN_SAMPLES), so the ML status payload must say so
explicitly instead of silently showing a model that never fires, and
hybrid_risk must keep the rule-weighted score when ML scores are empty.
"""

from __future__ import annotations


def test_status_warns_when_model_not_ready():
    """An untrained detector discloses that detections rely on rules."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector(load_persisted=False)
    detector.models = {}  # force not-ready regardless of persisted bundles
    status = detector.status()
    assert status["ready"] is False
    assert status["ml_contribution"] == "not_ready"
    assert status["warning"], "not-ready ML must surface an operator warning"
    assert "ML_TRAIN_MIN_SAMPLES" in status["warning"]
    assert isinstance(status["zero_anomaly_streams"], list)


def test_status_warns_when_zero_anomalies_flagged():
    """A ready model with no flagged anomalies warns (0-anomaly cold start)."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector(load_persisted=False)
    # Ready (models present) but the clean test DB has no ml_score rows, so
    # nothing in the scoring window is flagged above threshold.
    detector.models = {"login": object(), "process": object()}
    status = detector.status()
    assert status["ready"] is True
    assert status["ml_contribution"] == "zero_anomaly"
    assert status["warning"], "zero-flagged ML must surface an operator warning"
    assert "ML has not flagged anomalies yet" in status["warning"]
    assert "ML_TRAIN_MIN_SAMPLES" in status["warning"]
    assert set(status["zero_anomaly_streams"]) >= {"login", "process"}


def test_ml_status_api_exposes_contribution_warning():
    """/api/system/ml/status carries the contribution fields for the UI."""
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/ml/status")
        assert r.status_code == 200
        body = r.json()
    assert "ml_contribution" in body
    assert "zero_anomaly_streams" in body
    assert "warning" in body
    if body["ml_contribution"] != "active":
        assert body["warning"], "non-active ML contribution must carry a warning"


def test_hybrid_risk_rule_only_when_ml_scores_empty():
    """Empty ml_scores must never drop the rule-weighted risk to 0."""
    from backend.risk.scoring import hybrid_parts, hybrid_risk

    final, level = hybrid_risk("high", 0.9, 1, [])
    assert final > 0, "rule-only hybrid risk must stay > 0"
    assert level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    final2, rule_part, ml_part, _ = hybrid_parts("high", 0.9, 1, [])
    assert ml_part == 0.0, "no ML scores -> zero ML part"
    assert rule_part > 0, "rule part must survive with no ML scores"
    assert final2 == rule_part
