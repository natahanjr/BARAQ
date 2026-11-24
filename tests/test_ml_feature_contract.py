"""Feature-space contract tests for the BARAQ ML layer.

These are the tests that were missing. Each one corresponds to a defect found
in the ML assessment:

  ML-1  shipped bundle's feature_version must equal ML_FEATURE_VERSION
  ML-2  live builder width must equal the model's n_features_in_
  ML-3  no feature may be derived from the ground-truth labeler
  ML-4  no bare /8 may be treated as an attack prefix
  ML-5  is_attack_ip_offline must not use bare /8 prefixes either
  ML-6  feature_psi must not crash on dimension mismatch
  ML-7  declared dimensions must match what the builders actually emit
  ML-8  _tune_threshold must not clamp CFAR to [0.05, 0.98]

Run:
    python -m pytest tests/test_ml_feature_contract.py -q
"""

from __future__ import annotations

import os
import warnings
from datetime import UTC, datetime

import pytest

warnings.filterwarnings("ignore")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("BARAQ_SKIP_SECRET_GEN", "1")
os.environ.setdefault("BARAQ_DATABASE_URL", "sqlite:///./_contract_test.db")
os.environ.setdefault("BARAQ_API_KEYS", '{"k-admin":"admin","k-analyst":"analyst"}')
os.environ.setdefault("BARAQ_ADMIN_PASSWORD", "TestOnly-NotReal-9x2")
os.environ.setdefault("BARAQ_TOKEN_SECRET", "a" * 64)
os.environ.setdefault("BARAQ_ENCRYPT_AT_REST", "0")

import joblib  # noqa: E402

BUNDLE = os.path.join(ROOT, "backend", "ml", "assets", "bootstrap_model.joblib")


def _login_event() -> dict:
    return {
        "event_id": 4624,
        "ts": datetime.now(UTC),
        "user": "alice",
        "host": "ws-01",
        "category": "Authentication",
        "facts": {"logon_type": 2, "source_ip": "10.0.0.5", "target_user": "alice"},
        "raw": {"logon_type": 2, "source_ip": "10.0.0.5"},
    }


def _process_event() -> dict:
    return {
        "event_id": 4688,
        "ts": datetime.now(UTC),
        "user": "alice",
        "host": "ws-01",
        "category": "Process",
        "facts": {"process_name": "chrome.exe", "parent_process": "explorer.exe"},
        "raw": {"process_name": "chrome.exe", "parent_process": "explorer.exe"},
    }


# ---------------------------------------------------------------------------
# ML-6: declared dimensions match the builders
# ---------------------------------------------------------------------------
def test_login_builder_matches_declared_dim():
    from backend.ml.anomaly import FEATURE_DIM, event_feature_vector

    v = event_feature_vector(_login_event())
    assert v is not None
    assert len(v) == FEATURE_DIM["login"], (
        f"login builder emits {len(v)} features, FEATURE_DIM says "
        f"{FEATURE_DIM['login']}"
    )


def test_process_builder_matches_declared_dim():
    from backend.ml.anomaly import FEATURE_DIM, event_feature_vector

    v = event_feature_vector(_process_event())
    assert v is not None
    assert len(v) == FEATURE_DIM["process"], (
        f"process builder emits {len(v)} features, FEATURE_DIM says "
        f"{FEATURE_DIM['process']}"
    )


def test_network_builder_matches_declared_dim():
    from backend.ml.anomaly import NETWORK_FEATURE_DIM, MLAnomalyDetector

    v = MLAnomalyDetector._network_features("8.8.8.8", 1, 1)
    assert len(v) == NETWORK_FEATURE_DIM, (
        f"network builder emits {len(v)} features, NETWORK_FEATURE_DIM says "
        f"{NETWORK_FEATURE_DIM}"
    )


# ---------------------------------------------------------------------------
# ML-1: the shipped artifact is loadable by the running config
# ---------------------------------------------------------------------------
def test_shipped_bundle_feature_version_matches_config():
    from backend.config import ML_FEATURE_VERSION

    if not os.path.isfile(BUNDLE):
        pytest.skip("no bootstrap bundle shipped")
    bundle = joblib.load(BUNDLE)
    assert bundle.get("feature_version") == ML_FEATURE_VERSION, (
        f"shipped bundle feature_version={bundle.get('feature_version')} but "
        f"config ML_FEATURE_VERSION={ML_FEATURE_VERSION}: the bundle is "
        f"rejected at load and the ML layer starts untrained"
    )


# ---------------------------------------------------------------------------
# ML-2: the shipped artifact's models accept the live vectors
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("stream", ["login", "process", "network"])
def test_shipped_model_accepts_live_vector_width(stream):
    from backend.ml.anomaly import FEATURE_DIM

    if not os.path.isfile(BUNDLE):
        pytest.skip("no bootstrap bundle shipped")
    bundle = joblib.load(BUNDLE)
    model = bundle.get("models", {}).get(stream)
    if model is None:
        pytest.skip(f"bundle has no {stream} model")

    assert model.n_features_in_ == FEATURE_DIM[stream], (
        f"{stream}: model trained on {model.n_features_in_} features but the "
        f"live builder emits {FEATURE_DIM[stream]}. Scoring would silently "
        f"return 0.0 (maximally normal) for every event."
    )


def test_score_with_reports_mismatch_instead_of_silent_zero():
    """A width mismatch must be observable, not a silent 0.0."""
    from backend.ml import anomaly as A

    if not os.path.isfile(BUNDLE):
        pytest.skip("no bootstrap bundle shipped")
    bundle = joblib.load(BUNDLE)
    model = bundle["models"]["network"]

    before = A.feature_mismatch_count()
    wrong = [0.0] * (model.n_features_in_ + 5)
    score = A.MLAnomalyDetector._score_with(model, wrong)
    after = A.feature_mismatch_count()

    assert score == 0.0
    assert after > before, (
        "a feature-width mismatch returned 0.0 without incrementing the "
        "mismatch counter: the failure is invisible to operators"
    )


# ---------------------------------------------------------------------------
# ML-3: no feature may be derived from the ground-truth labeler
# ---------------------------------------------------------------------------
def test_network_vector_does_not_encode_the_label():
    """Two IPs that differ only in labeler output must not differ in features
    by virtue of that label."""
    from backend.ml.anomaly import MLAnomalyDetector
    from backend.ml.realworld_labeler import is_attack_ip_offline

    benign_ip = "8.8.8.8"
    attack_ip = "45.33.32.156"

    if not is_attack_ip_offline(attack_ip):
        pytest.skip("labeler no longer flags the probe IP")

    a = MLAnomalyDetector._network_features(benign_ip, 1, 1)
    b = MLAnomalyDetector._network_features(attack_ip, 1, 1)

    # The IP-derived numeric features legitimately differ (they encode the
    # address). What must NOT differ is a dedicated label slot. Slot 21 was
    # `is_atk`; it must now be constant.
    assert a[21] == b[21] == 0.0, (
        f"slot 21 tracks the labeler ({a[21]} vs {b[21]}): the ground-truth "
        f"label is exposed as a feature (label leakage)"
    )


# ---------------------------------------------------------------------------
# ML-4: no bare /8 treated as an attack prefix
# ---------------------------------------------------------------------------
def test_no_bare_octet_attack_prefixes():
    from backend.ml.anomaly import _NET_ATTACK_PREFIXES

    for prefix in _NET_ATTACK_PREFIXES:
        octets = [p for p in prefix.split(".") if p]
        assert len(octets) >= 3, (
            f"attack prefix {prefix!r} is wider than a /24; a bare octet "
            f"labels millions of legitimate addresses as malicious"
        )


# ---------------------------------------------------------------------------
# ML-5: is_attack_ip_offline must not use bare /8 prefixes either
# ---------------------------------------------------------------------------
def test_is_attack_ip_offline_no_bare_octet():
    from backend.ml.realworld_labeler import is_attack_ip_offline

    # 45.x.x.x was a bare /8 that labeled 16.7M addresses (OVH/Linode etc.)
    # as malicious. It must NOT be treated as attack by the offline labeler.
    assert is_attack_ip_offline("45.33.32.156") is False
    assert is_attack_ip_offline("45.0.0.1") is False
    assert is_attack_ip_offline("45.255.255.255") is False

    # Legitimate documentation ranges still flagged
    assert is_attack_ip_offline("203.0.113.66") is True
    assert is_attack_ip_offline("198.51.100.66") is True
    assert is_attack_ip_offline("192.0.2.66") is True


# ---------------------------------------------------------------------------
# ML-6: feature_psi must not crash on dimension mismatch
# ---------------------------------------------------------------------------
def test_feature_psi_dimension_mismatch_returns_empty():
    """feature_psi compares feature distributions. If reference and current
    have different column counts (e.g. score CDF vs feature matrix), it must
    return [] rather than crash or silently produce wrong results.

    This guards the drift detector: detector.baselines stores score CDFs
    (1-D), while live features are 2-D matrices. Calling feature_psi(baseline,
    X) with mismatched dimensions must return [] so check_drift doesn't
    report false "no feature drift" results.
    """
    from backend.ml.drift import feature_psi
    import numpy as np

    rng = np.random.RandomState(42)

    # 1-D reference (score CDF) vs 2-D current (feature matrix): dimensions
    # don't match, must return []
    ref_1d = rng.normal(0.5, 0.1, 100)
    cur_2d = rng.normal(0.5, 0.1, (50, 7))
    assert feature_psi(ref_1d, cur_2d) == []

    # 2-D reference with different column count vs 2-D current: also []
    ref_2d = rng.normal(0.5, 0.1, (100, 3))
    cur_2d = rng.normal(0.5, 0.1, (50, 7))
    assert feature_psi(ref_2d, cur_2d) == []

    # Matching dimensions: should return per-feature PSI values
    ref_match = rng.normal(0.5, 0.1, (100, 3))
    cur_match = rng.normal(0.5, 0.1, (50, 3))
    result = feature_psi(ref_match, cur_match)
    assert len(result) == 3
    assert all(isinstance(p, float) for p in result)


# ---------------------------------------------------------------------------
# ML-8: _tune_threshold must not clamp CFAR to [0.05, 0.98]
# ---------------------------------------------------------------------------
def test_tune_threshold_does_not_clamp_low_scores():
    """Probability-calibrated scores cluster near 1e-3 for benign events.
    The old code clamped the CFAR quantile to [0.05, 0.98], raising the
    threshold 50x and silently disabling the stream.  The quantile must be
    returned as-is, even when far below 0.05.
    """
    from backend.ml.anomaly import MLAnomalyDetector
    import numpy as np

    rng = np.random.RandomState(7)

    # Benign scores clustered near 1e-3 (typical for calibrated models),
    # attacks near 0.9.
    benign = rng.normal(0.001, 0.0005, 400)
    attacks = rng.normal(0.9, 0.05, 20)
    scores = np.concatenate([benign, attacks])
    labels = np.array([0] * 400 + [1] * 20)

    # Mock model whose decision_function returns the raw scores directly.
    class _MockModel:
        def decision_function(self, X):
            return np.asarray(X).ravel()

    model = _MockModel()
    X = scores.reshape(-1, 1)
    threshold, _ = MLAnomalyDetector._tune_threshold(
        model, X, labels, target_fpr=0.05, stream_name="login"
    )

    # With benign at ~0.001, the 95th percentile of benign is ~0.0018 — well
    # below the old clamp floor of 0.05.  The threshold must stay low, not
    # be clamped up to 0.05.
    assert threshold < 0.05, (
        f"threshold {threshold:.4f} was clamped to the old 0.05 floor; "
        "calibrated benign scores near 1e-3 must not be clamped"
    )
    assert threshold > 0.0, "threshold should be positive, not zero"
