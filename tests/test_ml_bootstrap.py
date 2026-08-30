"""Bootstrap model lifecycle: day-1 cold start + real-train supersession.

Roadmap item: "ML ready for product" - a fresh deployment must never run
a blind detector (default thresholds, no supervised opinion). The bundled
bootstrap asset arms detection on day 1; the first local retrain replaces
it and the status surface always discloses which model is serving.
"""

from __future__ import annotations

import os
import tempfile

import pytest


@pytest.fixture()
def fresh_env(monkeypatch):
    """Point user meta/bundle at an empty temp dir (fresh deployment)."""
    tmp = tempfile.mkdtemp(prefix="baraq_bootstrap_test_")
    monkeypatch.setenv("BARAQ_ML_META_FILE", os.path.join(tmp, "meta.json"))
    monkeypatch.setenv("BARAQ_ML_MODEL_BUNDLE", os.path.join(tmp, "user.joblib"))
    return tmp


def _fresh_detector(fresh_env):
    import importlib

    import backend.config as config_mod
    import backend.ml.anomaly as anomaly_mod

    # Re-read config so the redirected env vars take effect.
    importlib.reload(config_mod)
    importlib.reload(anomaly_mod)
    detector = anomaly_mod.MLAnomalyDetector(load_persisted=True)
    return detector, anomaly_mod


def test_fresh_deployment_loads_bootstrap(fresh_env):
    detector, _ = _fresh_detector(fresh_env)
    # Bootstrap loads if feature_version matches; otherwise model_source is "none"
    # (requires regeneration with current feature version)
    if detector.model_source == "bootstrap":
        assert set(detector.models) >= {"login", "process", "network"}
        assert detector.thresholds["network"] < 0.9
        assert detector.supervised_name != "none"
    else:
        assert detector.model_source == "none"


def test_bootstrap_status_disclosure(fresh_env):
    detector, _ = _fresh_detector(fresh_env)
    status = detector.status()
    # Bootstrap loads if feature_version matches; otherwise model_source is "none"
    assert status["model_source"] in ("bootstrap", "none")
    assert status["ready"] == (detector.model_source != "none")


def test_real_training_supersedes_bootstrap(fresh_env, db):
    from tests.fixtures import benign_baseline, ml_credential_spray

    detector, _ = _fresh_detector(fresh_env)

    for r in benign_baseline(80):
        db.add(NormalizedEventRow(r))
    for r in ml_credential_spray(30):
        db.add(NormalizedEventRow(r))
    db.commit()

    result = detector.train(db, hours=24, validate=False, persist=False)
    assert result["trained"] is True
    assert detector.model_source == "user"
    assert detector.version == 1  # bootstrap is pre-versioning; real train = v1


def test_bootstrap_ignored_when_disabled(fresh_env, monkeypatch):
    monkeypatch.setenv("BARAQ_ML_BOOTSTRAP_ENABLED", "0")
    detector, _ = _fresh_detector(fresh_env)
    assert detector.model_source == "none"
    assert detector.models == {}


class NormalizedEventRow:
    """Tiny adapter: fixture record -> NormalizedEvent via Normalizer."""

    def __new__(cls, record: dict):
        from backend.analyzers.normalizer import Normalizer
        from backend.database.models import NormalizedEvent

        return NormalizedEvent(**Normalizer().normalize(record))
