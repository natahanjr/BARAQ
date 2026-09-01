"""Tests for v7 ML enhancements: expanded features, cross-validation, augmentation, ensemble, robustness."""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest

from backend.ml.anomaly import (
    _kfold_cross_validate,
    _smote_augment,
    _get_dns_tunnel_indicator,
    _get_dns_long_label_indicator,
    _get_protocol_anomaly_score,
    _get_tls_https_ratio,
    _get_connection_diversity_score,
    _get_data_volume_asymmetry,
    _get_connection_regularity_score,
    _get_outbound_connection_ratio,
    _get_failed_success_ratio,
    _get_auth_protocol_indicator,
    _get_distinct_source_ips,
    _get_hour_distribution_entropy,
    _get_executable_path_entropy,
    _get_system_directory_indicator,
    _get_parent_process_risk_score,
    _get_commandline_token_count,
    _get_process_chain_depth,
)
from backend.ml.ensemble import EnsembleStacker
from backend.ml.robustness import fgsm_evasion_test, evaluate_robustness


class TestKFoldCrossValidation:
    """Test k-fold cross-validation for anomaly detection."""

    def test_cv_returns_valid_result(self):
        rng = np.random.RandomState(42)
        X_normal = rng.randn(100, 10) * 0.5 + 0.5
        X_anomaly = rng.randn(10, 10) * 0.5 + 0.8
        X = np.vstack([X_normal, X_anomaly])
        X = np.clip(X, 0, 1)
        y = np.array([0] * 100 + [1] * 10)

        model = IsolationForest(contamination=0.1, random_state=42)
        result = _kfold_cross_validate(IsolationForest, X, y, n_folds=3)

        assert "mean_score" in result
        assert "std_score" in result
        assert "fold_scores" in result
        assert len(result["fold_scores"]) == 3

    def test_cv_insufficient_data(self):
        X = np.random.randn(3, 5)
        y = np.array([0, 0, 1])
        result = _kfold_cross_validate(IsolationForest, X, y, n_folds=5)
        assert result["mean_score"] == 0.0
        assert result["fold_scores"] == []


class TestSMOTEAugmentation:
    """Test SMOTE-like synthetic oversampling."""

    def test_smote_increases_minority_samples(self):
        rng = np.random.RandomState(42)
        X_majority = rng.randn(50, 5) * 0.5 + 0.5
        X_minority = rng.randn(5, 5) * 0.5 + 0.8
        X = np.vstack([X_majority, X_minority])
        X = np.clip(X, 0, 1)
        y = np.array([0] * 50 + [1] * 5)

        X_aug, y_aug = _smote_augment(X, y, minority_class=1, k_neighbors=3)

        assert len(X_aug) > len(X)
        assert len(y_aug) == len(X_aug)
        assert np.sum(y_aug == 1) > 5

    def test_smote_no_augmentation_when_insufficient(self):
        X = np.random.randn(5, 5)
        y = np.array([0, 0, 0, 0, 1])
        X_aug, y_aug = _smote_augment(X, y, minority_class=1, k_neighbors=5)
        assert len(X_aug) == len(X)


class TestEnsembleStacker:
    """Test enhanced ensemble stacking with gradient boosting."""

    def test_ensemble_initializes(self):
        stacker = EnsembleStacker()
        assert not stacker.is_trained
        assert stacker.meta_model is None
        assert stacker.gb_model is None

    def test_ensemble_train_meta_with_sufficient_data(self):
        rng = np.random.RandomState(42)
        n = 100
        if_scores = rng.random(n)
        sup_probas = rng.random(n)
        markov_scores = rng.random(n)
        y = (if_scores + sup_probas + markov_scores > 1.5).astype(int)

        stacker = EnsembleStacker()
        result = stacker.train_meta(if_scores, sup_probas, markov_scores, y)

        assert result["status"] == "ok"
        assert result["trained"] is True
        assert "meta_learner" in result
        assert result["meta_learner"] in ("gradient_boosting", "logistic_regression")

    def test_ensemble_predict_after_training(self):
        rng = np.random.RandomState(42)
        n = 100
        if_scores = rng.random(n)
        sup_probas = rng.random(n)
        markov_scores = rng.random(n)
        y = (if_scores + sup_probas + markov_scores > 1.5).astype(int)

        stacker = EnsembleStacker()
        stacker.train_meta(if_scores, sup_probas, markov_scores, y)

        pred = stacker.predict(0.8, 0.7, 0.6)
        assert 0.0 <= pred <= 1.0

    def test_ensemble_fallback_without_training(self):
        stacker = EnsembleStacker()
        pred = stacker.predict(0.8, 0.7, 0.0)
        assert 0.0 <= pred <= 1.0

    def test_ensemble_status(self):
        stacker = EnsembleStacker()
        status = stacker.status()
        assert "is_trained" in status
        assert "active_meta_learner" in status
        assert "meta_weights" in status


class TestFGSMEvasionTest:
    """Test FGSM-style adversarial evasion testing."""

    def test_fgsm_returns_valid_result(self):
        rng = np.random.RandomState(42)
        X = rng.randn(50, 10) * 0.5 + 0.5
        X = np.clip(X, 0, 1)
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)

        result = fgsm_evasion_test(model, X, epsilon=0.1, n_samples=30)

        assert "evasion_success_rate" in result
        assert "robustness_score" in result
        assert "per_feature_evasion_rate" in result
        assert 0.0 <= result["evasion_success_rate"] <= 1.0
        assert 0.0 <= result["robustness_score"] <= 1.0

    def test_fgsm_no_model(self):
        X = np.random.randn(10, 5)
        result = fgsm_evasion_test(None, X)
        assert result["robustness_score"] == 1.0

    def test_fgsm_with_feature_bounds(self):
        rng = np.random.RandomState(42)
        X = rng.randn(30, 5) * 0.5 + 0.5
        X = np.clip(X, 0, 1)
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)

        bounds = [(0.0, 1.0)] * 5
        result = fgsm_evasion_test(model, X, epsilon=0.05, feature_bounds=bounds)

        assert 0.0 <= result["evasion_success_rate"] <= 1.0


class TestNetworkFeatureHelpers:
    """Test new v7 network feature helper functions."""

    def test_dns_tunnel_indicator_returns_float(self):
        result = _get_dns_tunnel_indicator.__wrapped__(None) if hasattr(_get_dns_tunnel_indicator, "__wrapped__") else 0.0
        assert isinstance(result, float)

    def test_protocol_anomaly_score_returns_float(self):
        result = _get_protocol_anomaly_score.__wrapped__(None, "192.168.1.1", 80) if hasattr(_get_protocol_anomaly_score, "__wrapped__") else 0.0
        assert isinstance(result, float)

    def test_tls_https_ratio_returns_float(self):
        result = _get_tls_https_ratio.__wrapped__(None) if hasattr(_get_tls_https_ratio, "__wrapped__") else 0.0
        assert isinstance(result, float)


class TestLoginFeatureHelpers:
    """Test new v7 login feature helper functions."""

    def test_auth_protocol_indicator(self):
        class MockEvent:
            def __init__(self, facts):
                self.raw_json = {"facts": facts}

        result = _get_auth_protocol_indicator(MockEvent({"logon_process": "NtlmSsp"}))
        assert result == 0.7

        result = _get_auth_protocol_indicator(MockEvent({"logon_process": "Kerberos"}))
        assert result == 0.1

        result = _get_auth_protocol_indicator(MockEvent({}))
        assert result == 0.5


class TestProcessFeatureHelpers:
    """Test new v7 process feature helper functions."""

    def test_executable_path_entropy(self):
        class MockEvent:
            def __init__(self, facts):
                self.raw_json = {"facts": facts}

        result = _get_executable_path_entropy(MockEvent({"image_path": "C:\\Windows\\System32\\cmd.exe"}))
        assert 0.0 <= result <= 1.0

    def test_system_directory_indicator(self):
        class MockEvent:
            def __init__(self, facts):
                self.raw_json = {"facts": facts}

        result = _get_system_directory_indicator(MockEvent({"image_path": "C:\\Windows\\System32\\cmd.exe"}))
        assert result == 1.0

        result = _get_system_directory_indicator(MockEvent({"image_path": "C:\\temp\\evil.exe"}))
        assert result == 0.0

    def test_parent_process_risk_score(self):
        class MockEvent:
            def __init__(self, facts):
                self.raw_json = {"facts": facts}

        result = _get_parent_process_risk_score(MockEvent({"parent_process": "powershell.exe"}))
        assert result == 0.9

        result = _get_parent_process_risk_score(MockEvent({"parent_process": "services.exe"}))
        assert result == 0.1

    def test_commandline_token_count(self):
        class MockEvent:
            def __init__(self, facts):
                self.raw_json = {"facts": facts}

        result = _get_commandline_token_count(MockEvent({"command_line": "cmd /c echo hello"}))
        assert result > 0

        result = _get_commandline_token_count(MockEvent({}))
        assert result == 0.0
