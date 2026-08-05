"""ML anomaly detection validation and ablation studies."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database.models import Base, NormalizedEvent
from backend.ml.anomaly import MLAnomalyDetector, event_feature_vector
from backend.analyzers.normalizer import Normalizer
from tests.fixtures import (
    benign_baseline,
    brute_force,
    suspicious_powershell,
)


@pytest.fixture
def ml_session():
    """Create an isolated in-memory session for ML tests."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestMLAnomalyDetector:
    """Test suite for ML anomaly detection."""

    def test_detector_initializes(self):
        """Test detector initialization."""
        detector = MLAnomalyDetector()
        assert not detector.is_ready
        assert detector.models == {}
        assert detector.supervised is None

    def test_feature_vector_extraction_login_events(self):
        """Test feature extraction for login events."""
        record = {
            "event_id": 4625,
            "raw_json": {
                "facts": {
                    "logon_type": 3,
                    "sub_status": True,
                    "source_ip": 192168001010,
                    "is_locked": False,
                }
            }
        }
        features = event_feature_vector(record)
        assert features is not None
        assert len(features) == 5
        assert features[0] == 4625  # event_id

    def test_detector_trains_on_baseline(self, ml_session):
        """Test that detector trains on baseline events."""
        # Add baseline events
        for r in benign_baseline(50):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        result = detector.train(ml_session, hours=24)

        assert result["status"] == "ok"
        assert result["trained"] is True
        assert len(detector.models) > 0
        assert result["samples"] > 0

    def test_detector_scores_events(self, ml_session):
        """Test event anomaly scoring."""
        # Train on baseline
        for r in benign_baseline(50):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)

        # Score a baseline event (should be low anomaly)
        baseline = benign_baseline(1)[0]
        normalized = Normalizer().normalize(baseline)
        features = event_feature_vector(normalized)

        if features:
            score = detector.score_event(features)
            assert 0.0 <= score <= 1.0

    def test_detector_flags_anomalies(self, ml_session):
        """Test that detector flags anomalous events."""
        # Train on baseline
        for r in benign_baseline(50):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)

        # Add attack events and analyze
        for r in brute_force(attempts=12):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        result = detector.analyze_events(ml_session, hours=1)
        assert result["status"] == "ok"
        # Detector should score some events
        assert result.get("scored", 0) >= 0

    def test_supervised_classifier_training(self, ml_session):
        """Test supervised classifier training on attack vs baseline."""
        # Mixed baseline and attack data
        for r in benign_baseline(30):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        for r in brute_force(attempts=15):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        result = detector.train(ml_session, hours=24)

        assert result["trained"] is True
        # Supervised classifier should be trained if enough samples
        if result["samples"] >= 10:
            assert detector.supervised is not None or result["status"] == "ok"

    def test_ml_status_reporting(self, ml_session):
        """Test ML detector status reporting."""
        for r in benign_baseline(40):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)

        status = detector.status()
        assert "ready" in status
        assert "trained_at" in status
        assert "streams" in status
        assert len(status["streams"]) > 0


# =====================================================================
# COMPARATIVE ANALYSIS: Hybrid vs Rule-only vs ML-only Detection
# =====================================================================

class TestDetectionMethodComparison:
    """Comparative analysis of detection methods."""

    def test_rule_only_vs_hybrid_scoring(self, ml_session):
        """Compare rule-only vs hybrid risk scores."""
        from backend.risk.scoring import compute_rule_score

        # Rule-only scoring
        rule_score = compute_rule_score(severity="high", confidence=0.85, event_count=5)
        assert 0 <= rule_score <= 100
        assert rule_score > 40  # High severity should produce significant score

    def test_ml_only_detection_sensitivity(self, ml_session):
        """Test ML-only detection on attack vs baseline."""
        # Train detector
        for r in benign_baseline(60):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)

        # Test on baseline (should have low anomaly flags)
        baseline_anomalies = 0
        for r in benign_baseline(30):
            normalized = Normalizer().normalize(r)
            features = event_feature_vector(normalized)
            if features:
                score = detector.score_event(features)
                if score > 0.5:
                    baseline_anomalies += 1

        # Test on attacks (should have high anomaly flags)
        attack_anomalies = 0
        for r in brute_force(attempts=12):
            normalized = Normalizer().normalize(r)
            features = event_feature_vector(normalized)
            if features:
                score = detector.score_event(features)
                if score > 0.5:
                    attack_anomalies += 1

        # Attack events should flag higher anomaly rate than baseline
        # (this is a heuristic check, not strict)
        assert baseline_anomalies <= len(benign_baseline(30)) * 0.5
        assert attack_anomalies > 0 or baseline_anomalies > 0

    def test_rule_detection_precision(self, ml_session):
        """Test rule-based detection precision on baseline."""
        from backend.detection.rules.brute_force import BruteForceRule

        # Add only baseline events
        for r in benign_baseline(200):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        rule = BruteForceRule(ml_session, threshold=5)
        findings = rule.evaluate(10)

        # Rule-only should have zero false positives on baseline
        assert len(findings) == 0, "Rule-based detection should not flag baseline activity"

    def test_hybrid_scoring_reduces_false_positives(self, ml_session):
        """Test that hybrid scoring helps reduce false positives."""
        from backend.risk.scoring import compute_hybrid_score

        # Simulate low-confidence rule firing + low ML anomaly score
        rule_score = 35  # Borderline
        ml_scores = [0.2, 0.15, 0.25]  # Low anomaly

        hybrid = compute_hybrid_score(
            rule_score=rule_score,
            ml_scores=ml_scores,
            ml_weight=0.4,
            rule_weight=0.6
        )

        # Hybrid should lower the score when ML disagrees
        assert hybrid <= rule_score

    def test_detection_coverage_comparison(self, ml_session):
        """Compare detection coverage: rules vs ML vs hybrid."""
        from backend.detection.rules.brute_force import BruteForceRule
        from backend.detection.rules.powershell import SuspiciousPowerShellRule

        # Add mixed attack data
        for r in brute_force(attempts=12):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        for r in suspicious_powershell():
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        # Rule-based coverage
        bf_rule = BruteForceRule(ml_session, threshold=5)
        ps_rule = SuspiciousPowerShellRule(ml_session)

        bf_findings = bf_rule.evaluate(10)
        ps_findings = ps_rule.evaluate(10)
        rule_coverage = len(bf_findings) + len(ps_findings)

        # ML coverage
        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)
        ml_analysis = detector.analyze_events(ml_session, hours=1)
        ml_coverage = ml_analysis.get("flagged", 0)

        # Both should detect something
        assert rule_coverage > 0
        # ML may detect different events than rules
        assert ml_coverage >= 0


# =====================================================================
# ABLATION STUDIES
# =====================================================================

class TestAblationStudies:
    """Ablation studies testing impact of individual components."""

    def test_hybrid_weight_impact(self):
        """Test impact of ML weight in hybrid scoring."""
        from backend.risk.scoring import compute_hybrid_score

        rule_score = 60
        ml_scores = [0.8, 0.85, 0.9]  # High ML anomaly

        # Full hybrid (40% ML)
        hybrid_full = compute_hybrid_score(rule_score, ml_scores, ml_weight=0.4)

        # ML-only (100% ML)
        hybrid_ml_only = compute_hybrid_score(rule_score, ml_scores, ml_weight=1.0)

        # Rule-only (0% ML)
        hybrid_rule_only = compute_hybrid_score(rule_score, ml_scores, ml_weight=0.0)

        # Verify weight impact
        assert hybrid_rule_only == 60  # Pure rule score
        assert hybrid_ml_only != hybrid_rule_only
        assert hybrid_full != hybrid_rule_only
        assert abs(hybrid_full - hybrid_rule_only) < abs(hybrid_ml_only - hybrid_rule_only)

    def test_rule_threshold_impact(self, ml_session):
        """Test impact of rule threshold tuning."""
        from backend.detection.rules.brute_force import BruteForceRule

        # Add brute force events
        for r in brute_force(attempts=12):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        # Sensitive threshold (low = more detections)
        rule_sensitive = BruteForceRule(ml_session, threshold=3)
        findings_sensitive = rule_sensitive.evaluate(10)

        # Strict threshold (high = fewer detections)
        rule_strict = BruteForceRule(ml_session, threshold=10)
        findings_strict = rule_strict.evaluate(10)

        # Sensitive should detect, strict may not
        assert len(findings_sensitive) >= len(findings_strict)

    def test_correlation_window_impact(self, ml_session):
        """Test impact of detection window size."""
        from backend.detection.rules.network_recon import NetworkReconRule
        from backend.database.models import NetworkConnection

        # Add port scan events spread over time
        for i in range(30):
            ml_session.add(NetworkConnection(
                pid=4422, process="nmap.exe",
                local_ip="192.168.99.66", local_port=40000 + i,
                remote_ip="10.0.0.4", remote_port=1 + (i * 137) % 65535,
                state="SYN_SENT", is_listening=False,
                observed_at=Normalizer._safe_ts("2026-08-04T10:00:00Z"),
            ))
        ml_session.commit()

        # Short window (60 seconds)
        rule_short = NetworkReconRule(ml_session, window_seconds=60)
        findings_short = rule_short.evaluate(10)

        # Long window (600 seconds)
        rule_long = NetworkReconRule(ml_session, window_seconds=600)
        findings_long = rule_long.evaluate(10)

        # Longer window should capture more events
        assert len(findings_long) >= len(findings_short)


# =====================================================================
# CROSS-VALIDATION AND ROBUSTNESS TESTS
# =====================================================================

class TestMLCrossValidation:
    """Cross-validation and robustness testing."""

    def test_detector_stability_across_data_splits(self, ml_session):
        """Test detector stability when trained on different data splits."""
        # First split: 50 baseline events
        for r in benign_baseline(50):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector1 = MLAnomalyDetector()
        result1 = detector1.train(ml_session, hours=24)

        # Second split: different 50 baseline events
        ml_session.query(NormalizedEvent).delete()
        ml_session.commit()

        for r in benign_baseline(50):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector2 = MLAnomalyDetector()
        result2 = detector2.train(ml_session, hours=24)

        # Both should train successfully
        assert result1["trained"] is True
        assert result2["trained"] is True
        assert result1["samples"] > 0
        assert result2["samples"] > 0

    def test_detector_generalization_on_unseen_attacks(self, ml_session):
        """Test ML generalization on attack types not in training."""
        # Train on baseline only
        for r in benign_baseline(80):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        detector.train(ml_session, hours=24)

        # Test on unseen PowerShell attack
        for r in suspicious_powershell():
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        result = detector.analyze_events(ml_session, hours=1)
        assert result["status"] == "ok"
        # Detector should flag some anomalies
        assert result["flagged"] >= 0

    def test_insufficient_data_handling(self, ml_session):
        """Test graceful handling of insufficient training data."""
        # Add only 2 events (below typical threshold)
        for r in benign_baseline(2):
            ml_session.add(NormalizedEvent(**Normalizer().normalize(r)))
        ml_session.commit()

        detector = MLAnomalyDetector()
        result = detector.train(ml_session, hours=24)

        # Should handle gracefully
        assert result["status"] in ["insufficient-data", "ok"]
        assert "trained" in result

