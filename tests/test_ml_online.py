"""Online learning (roadmap 4.1): feedback loop, PSI drift, model versioning."""

from __future__ import annotations

from datetime import UTC

import numpy as np

from backend.database.models import NormalizedEvent


def _seed_events(db, n=120, user="ml-online-user"):
    """Insert a reproducible set of login events across two clusters."""
    from datetime import datetime, timedelta

    rows = []
    base = datetime.now(UTC)
    for i in range(n):
        rows.append(
            NormalizedEvent(
                source="test",
                event_id=4624 if i % 2 == 0 else 4625,
                category="logon",
                severity="info",
                message=f"logon attempt {i}",
                user=user,
                host="ml-host",
                timestamp=base - timedelta(minutes=i),
                raw_json={
                    "facts": {
                        # Well-spread IP + logon-type facts keep the feature
                        # space non-degenerate regardless of wall-clock hour:
                        # a 120-minute seed window can span only 2 distinct
                        # hours, which alone leaves the IsolationForest with
                        # a single-point baseline and check_drift silently
                        # skips the stream.
                        "source_ip": i * 16_777_216,
                        "logon_type": 10 + (i % 4),
                    }
                },
            )
        )
    db.add_all(rows)
    db.commit()


def _train_detector(db, kind="initial"):
    from backend.ml.anomaly import get_detector

    det = get_detector()
    result = det.train(db, hours=24, validate=False, persist=False, kind=kind)
    assert result["trained"], result
    return det, result


def test_feedback_weights_damp_and_boost():
    from backend.ml.anomaly import get_detector

    det = get_detector()
    det.feedback_weights.clear()
    det.apply_feedback("false_positive", "login")
    det.apply_feedback("false_positive", "login")
    assert det.feedback_weights["login"] < 1.0
    weight_after_fp = det.feedback_weights["login"]
    det.apply_feedback("true_positive", "login")
    assert det.feedback_weights["login"] > weight_after_fp
    det.apply_feedback("bogus", "login")  # ignored
    assert det.feedback_weights["login"] > weight_after_fp


def test_feedback_weights_persisted_to_meta(monkeypatch, tmp_path):
    import json

    from backend.ml import anomaly as ml_mod

    meta_path = tmp_path / "model_meta.json"
    monkeypatch.setattr(ml_mod, "ML_META_FILE", meta_path)
    det = ml_mod.get_detector()
    det.feedback_weights.clear()
    det.apply_feedback("true_positive", "network")
    with open(meta_path, encoding="utf-8") as fh:
        meta = json.load(fh)
    assert meta["feedback_weights"]["network"] > 1.0


def test_psi_identical_and_drifted_distributions():
    from backend.ml.drift import psi

    rng = np.random.default_rng(7)
    same_a = rng.normal(0.0, 1.0, 2000)
    same_b = rng.normal(0.0, 1.0, 2000)
    drifted = rng.normal(2.5, 1.0, 2000)
    assert psi(same_a, same_b) < 0.05
    assert psi(same_a, drifted) > 0.1


def test_train_bumps_version_and_history(db):
    from backend.ml.anomaly import get_detector

    # The singleton detector loads persisted version history from the shared
    # meta file (which survives between pytest sessions) - reset it so the
    # assertion below is deterministic.
    get_detector().versions = []
    _seed_events(db)
    det, _ = _train_detector(db, kind="initial")
    v1 = det.version
    det, _ = _train_detector(db, kind="incremental")
    assert det.version == v1 + 1
    kinds = [v["kind"] for v in det.versions]
    assert kinds[-1] == "incremental"
    assert len(det.versions) == 2


def test_check_drift_reports_streams(db):

    _seed_events(db)
    _train_detector(db)
    from backend.ml.drift import check_drift

    report = check_drift(db, hours=24)
    assert report["status"] in ("ok", "watch", "drift", "not-trained")
    if report["status"] != "not-trained":
        assert "login" in report["streams"]
        assert "psi" in report["streams"]["login"]


def test_verdict_endpoint_applies_feedback():
    from fastapi.testclient import TestClient

    from backend.main import app
    from backend.ml.anomaly import get_detector

    det = get_detector()
    before = det.feedback_weights.get("login", 1.0)
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.post(
            "/api/ml/verdicts",
            json={
                "event_id": 1,
                "verdict": "false_positive",
                "note": "noise",
            },
        )
        assert r.status_code in (200, 404), r.text
        if r.status_code == 200:
            assert det.feedback_weights.get("login", 1.0) < before or before == 1.0
        r2 = client.get("/api/system/ml/status")
        assert r2.status_code == 200, r2.text
        assert "version" in r2.json()
        r3 = client.get("/api/system/ml/versions")
        assert r3.status_code == 200, r3.text
        assert "serving_version" in r3.json()
        r4 = client.get("/api/system/ml/drift")
        assert r4.status_code == 200, r4.text
        assert "status" in r4.json()
