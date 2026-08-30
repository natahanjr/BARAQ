"""Tests for the Hybrid Risk Scoring Engine (Upgrade Module 5)."""

from __future__ import annotations

import pytest

from backend.risk.scoring import (
    hybrid_risk,
    ml_anomaly_score,
    risk_descriptor,
    risk_level,
    rule_score,
)


class FakeEvent:
    def __init__(self, ml_score):
        self.ml_score = ml_score


def test_rule_score_high_severity_dominates():
    assert rule_score("high", 0.9, 1) > rule_score("low", 0.9, 1)
    assert 0 <= rule_score("high", 0.9, 1) <= 100


def test_rule_score_increases_with_confidence_and_events():
    low_conf = rule_score("medium", 0.3, 1)
    high_conf = rule_score("medium", 0.95, 1)
    assert high_conf > low_conf
    many = rule_score("medium", 0.5, 20)
    assert many > rule_score("medium", 0.5, 1)


def test_ml_anomaly_score_averages_and_scales():
    assert ml_anomaly_score([FakeEvent(0.0)]) == 0.0
    assert ml_anomaly_score([FakeEvent(0.5), FakeEvent(0.9)]) == pytest.approx(
        70.0, abs=0.01
    )
    assert ml_anomaly_score([FakeEvent(None), FakeEvent(0.5)]) == 50.0
    assert ml_anomaly_score([]) == 0.0
    assert ml_anomaly_score([{"ml_score": 0.25}]) == 25.0


def test_hybrid_risk_fusion_weights():
    # Rule 60% + ML 40%: high severity base 70, confidence 1.0 -> rule part 42
    final, _level = hybrid_risk("high", 1.0, 1, [], rule_weight=0.6, ml_weight=0.4)
    assert final == pytest.approx(42.0, abs=0.5)
    # All rule + perfect ML -> CRITICAL
    final_max, level_max = hybrid_risk("critical", 1.0, 1, [FakeEvent(1.0)])
    assert final_max > 85
    assert level_max == "CRITICAL"


def test_risk_level_thresholds():
    assert risk_level(10) == "LOW"
    assert risk_level(40) == "MEDIUM"
    assert risk_level(64) == "MEDIUM"
    assert risk_level(65) == "HIGH"
    assert risk_level(84) == "HIGH"
    assert risk_level(85) == "CRITICAL"


def test_risk_descriptor_known_levels():
    assert risk_descriptor("HIGH").startswith("Prioritized")
    assert risk_descriptor("unknown") == "Unknown"
