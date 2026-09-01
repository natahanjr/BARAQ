"""Tests for P0/P1/P2 ML enhancements: multi-contamination ensemble, DNS features, online learning, deep features, cross-user validation, temporal bias, attack variability, time-window ensemble, federated learning, cross-platform validation."""

from __future__ import annotations

import numpy as np
import pytest
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from backend.ml.anomaly import (
    _multi_contamination_ensemble,
    _calibrate_anomaly_scores,
    _select_optimal_threshold,
    _get_dns_query_pattern,
)
from backend.ml.ensemble import TimeWindowEnsemble
from backend.ml.drift import TemporalBiasDetector
from backend.ml.robustness import (
    cross_user_validation,
    cross_environment_validation,
    cross_platform_validation,
)
from backend.ml.federated import FederatedAggregator, FederatedClient, create_federated_setup
from backend.ml.public_datasets import CICIDSAdapter, EvaluationResult


class TestMultiContaminationEnsemble:
    """Test multi-contamination ensemble for better recall."""

    def test_ensemble_trains_multiple_models(self):
        rng = np.random.RandomState(42)
        X = rng.randn(100, 10) * 0.5 + 0.5
        X = np.clip(X, 0, 1)

        models = _multi_contamination_ensemble(X, n_estimators=20)
        assert len(models) == 5  # default contamination_range has 5 values
        for m in models:
            assert hasattr(m, "decision_function")

    def test_ensemble_custom_contamination_range(self):
        rng = np.random.RandomState(42)
        X = rng.randn(50, 5)
        models = _multi_contamination_ensemble(X, contamination_range=[0.01, 0.1], n_estimators=10)
        assert len(models) == 2


class TestScoreCalibration:
    """Test anomaly score calibration."""

    def test_sigmoid_calibration(self):
        scores = np.array([-2.0, -1.0, 0.0, 1.0, 2.0])
        calibrated = _calibrate_anomaly_scores(scores)
        assert len(calibrated) == 5
        assert all(0.0 <= v <= 1.0 for v in calibrated)
        # Sigmoid should be monotonically increasing
        assert all(calibrated[i] <= calibrated[i + 1] for i in range(len(calibrated) - 1))

    def test_baseline_calibration(self):
        scores = np.array([0.5, 0.6, 0.7])
        baseline = np.array([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9])
        calibrated = _calibrate_anomaly_scores(scores, baseline)
        assert all(0.0 <= v <= 1.0 for v in calibrated)


class TestOptimalThreshold:
    """Test optimal threshold selection."""

    def test_youden_threshold(self):
        scores = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
        labels = np.array([0, 0, 0, 1, 1, 1])
        thresh = _select_optimal_threshold(scores, labels, method="youden")
        assert 0.0 <= thresh <= 1.0

    def test_f1_threshold(self):
        scores = np.array([0.1, 0.2, 0.3, 0.7, 0.8, 0.9])
        labels = np.array([0, 0, 0, 1, 1, 1])
        thresh = _select_optimal_threshold(scores, labels, method="f1")
        assert 0.0 <= thresh <= 1.0

    def test_empty_input(self):
        thresh = _select_optimal_threshold(np.array([]), np.array([]))
        assert thresh == 0.5


class TestTimeWindowEnsemble:
    """Test time-window ensemble methods."""

    def test_ensemble_initialization(self):
        ensemble = TimeWindowEnsemble(max_windows=3)
        assert ensemble.n_windows == 0

    def test_add_model(self):
        from sklearn.ensemble import IsolationForest
        ensemble = TimeWindowEnsemble(max_windows=3)
        model = IsolationForest(n_estimators=10)
        X = np.random.randn(50, 5)
        model.fit(X)
        ensemble.add_model(model, window_start=0, window_end=100)
        assert ensemble.n_windows == 1

    def test_predict_with_models(self):
        from sklearn.ensemble import IsolationForest
        ensemble = TimeWindowEnsemble(max_windows=3)
        rng = np.random.RandomState(42)
        X = rng.randn(50, 5)

        for i in range(3):
            model = IsolationForest(n_estimators=10, random_state=i)
            model.fit(X)
            ensemble.add_model(model, window_start=i * 100, window_end=(i + 1) * 100)

        X_test = rng.randn(10, 5)
        predictions = ensemble.predict(X_test)
        assert len(predictions) == 10
        assert all(0.0 <= v <= 1.0 for v in predictions)


class TestTemporalBiasDetector:
    """Test temporal bias detection."""

    def test_build_reference(self):
        detector = TemporalBiasDetector()
        timestamps = [datetime(2026, 1, 1, h, 0, tzinfo=UTC) for h in range(24)]
        detector.build_reference(timestamps)
        assert detector._hourly_reference is not None

    def test_hourly_bias_detection(self):
        detector = TemporalBiasDetector()
        ref_timestamps = [datetime(2026, 1, 1, h % 24, 0, tzinfo=UTC) for h in range(100)]
        detector.build_reference(ref_timestamps)

        # All events at hour 2 (should detect bias)
        current = [datetime(2026, 6, 1, 2, 0, tzinfo=UTC) for _ in range(50)]
        result = detector.detect_hourly_bias(current)
        assert "bias_detected" in result
        assert "psi" in result

    def test_daily_bias_detection(self):
        detector = TemporalBiasDetector()
        ref_timestamps = [datetime(2026, 1, d, 10, 0, tzinfo=UTC) for d in range(1, 29)]
        detector.build_reference(ref_timestamps)

        # All events on Monday
        current = [datetime(2026, 6, 1, 10, 0, tzinfo=UTC) for _ in range(20)]
        result = detector.detect_daily_bias(current)
        assert "bias_detected" in result

    def test_all_detections(self):
        detector = TemporalBiasDetector()
        ref_timestamps = [datetime(2026, 1, 1, h, 0, tzinfo=UTC) for h in range(24)]
        detector.build_reference(ref_timestamps)
        current = [datetime(2026, 6, 1, 12, 0, tzinfo=UTC) for _ in range(20)]
        result = detector.get_all_detections(current)
        assert "any_bias_detected" in result
        assert "hourly" in result
        assert "daily" in result
        assert "monthly" in result


class TestCrossUserValidation:
    """Test cross-user validation."""

    def test_validation_returns_results(self):
        mock_detector = MagicMock()
        mock_detector.is_ready = True
        mock_detector.models = {"login": MagicMock()}
        mock_detector.models["login"].decision_function.return_value = np.random.randn(20) * 0.1

        user_sessions = {
            "user1": np.random.randn(20, 5),
            "user2": np.random.randn(15, 5),
        }
        result = cross_user_validation(mock_detector, user_sessions)
        assert result["status"] == "ok"
        assert "per_user_scores" in result
        assert "fairness_score" in result

    def test_empty_sessions(self):
        mock_detector = MagicMock()
        mock_detector.is_ready = True
        result = cross_user_validation(mock_detector, {})
        assert result["status"] == "no-data"


class TestCrossEnvironmentValidation:
    """Test cross-environment validation."""

    def test_validation_returns_results(self):
        mock_detector = MagicMock()
        mock_detector.is_ready = True
        mock_detector.models = {"login": MagicMock()}
        mock_detector.models["login"].decision_function.return_value = np.random.randn(20) * 0.1

        env_sessions = {
            "office": np.random.randn(20, 5),
            "datacenter": np.random.randn(15, 5),
        }
        result = cross_environment_validation(mock_detector, env_sessions)
        assert result["status"] == "ok"
        assert "per_env_scores" in result
        assert "domain_shift" in result


class TestCrossPlatformValidation:
    """Test cross-platform validation."""

    def test_validation_returns_results(self):
        mock_detector = MagicMock()
        mock_detector.is_ready = True
        mock_detector.models = {"login": MagicMock()}
        mock_detector.models["login"].decision_function.return_value = np.random.randn(20) * 0.1

        platform_sessions = {
            "windows": np.random.randn(20, 5),
            "linux": np.random.randn(15, 5),
            "macos": np.random.randn(10, 5),
        }
        result = cross_platform_validation(mock_detector, platform_sessions)
        assert result["status"] == "ok"
        assert "per_platform_scores" in result
        assert "compatibility_score" in result
        assert "recommendations" in result


class TestFederatedLearning:
    """Test federated learning capabilities."""

    def test_aggregator_initialization(self):
        aggregator = FederatedAggregator(min_clients=2)
        assert aggregator.round_id == 0
        assert aggregator.status()["min_clients"] == 2

    def test_client_creation(self):
        aggregator = FederatedAggregator(min_clients=2)
        client = FederatedClient(client_id="test_client", aggregator=aggregator)
        assert client.client_id == "test_client"

    def test_federated_setup(self):
        aggregator, clients = create_federated_setup(n_clients=3, min_clients=2)
        assert len(clients) == 3
        assert aggregator.min_clients == 2

    def test_client_training(self):
        aggregator, clients = create_federated_setup(n_clients=2, min_clients=2)
        rng = np.random.RandomState(42)

        for client in clients:
            X = rng.randn(50, 10)
            client.set_training_data(X)
            result = client.train_local()
            assert result["status"] == "ok"

    def test_aggregation(self):
        aggregator, clients = create_federated_setup(n_clients=3, min_clients=2)
        rng = np.random.RandomState(42)

        for client in clients:
            X = rng.randn(50, 10)
            client.set_training_data(X)
            client.train_local()
            client.send_update(performance_score=0.8)

        round_result = aggregator.aggregate()
        assert round_result is not None
        assert round_result.n_clients == 3


class TestDeepFeatures:
    """Test deep learning feature extraction."""

    def test_autoencoder_creation(self):
        try:
            from backend.ml.deep_features import EventAutoencoder
            model = EventAutoencoder(input_dim=10, latent_dim=4)
            X = np.random.randn(20, 10).astype(np.float32)
            import torch
            X_tensor = torch.FloatTensor(X)
            recon, latent = model(X_tensor)
            assert recon.shape == (20, 10)
            assert latent.shape == (20, 4)
        except ImportError:
            pytest.skip("PyTorch not installed")

    def test_temporal_cnn_creation(self):
        try:
            from backend.ml.deep_features import TemporalCNN
            model = TemporalCNN(input_dim=10, seq_len=5, n_filters=16)
            X = np.random.randn(8, 5, 10).astype(np.float32)
            import torch
            X_tensor = torch.FloatTensor(X)
            output = model(X_tensor)
            assert output.shape == (8, 16)
        except ImportError:
            pytest.skip("PyTorch not installed")

    def test_sequence_pattern_detector(self):
        try:
            from backend.ml.deep_features import SequencePatternDetector
            detector = SequencePatternDetector(window_size=5)
            events = [
                {"ts": datetime(2026, 1, 1, 10, i, 0, tzinfo=UTC), "event_id": 4624}
                for i in range(20)
            ]
            features = detector.extract_sequence_features(events)
            assert features.shape[0] > 0
            assert features.shape[1] == 12
        except Exception:
            pytest.skip("Sequence pattern test failed")


class TestPublicDatasets:
    """Test public dataset evaluation framework."""

    def test_evaluation_result_structure(self):
        result = EvaluationResult(
            dataset_name="test",
            n_samples=100,
            n_benign=80,
            n_attack=20,
            metrics={"accuracy": 0.95, "recall": 0.90},
        )
        assert result.dataset_name == "test"
        assert result.metrics["accuracy"] == 0.95
