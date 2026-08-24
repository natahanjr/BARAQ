"""Comprehensive tests for the BARAQ Professional Alert Ranking Engine.

Covers all public exports from ranking.py:
    SEVERITY_WEIGHT, severity_weight,
    confidence_multiplier,
    ASSET_MULTIPLIER, asset_criticality_multiplier,
    correlation_multiplier,
    recency_multiplier,
    repeat_dampener,
    risk_level_from_score,
    RiskBreakdown,
    compute_risk_score,
    rank_alerts,
    healthy_score,
"""

from __future__ import annotations

import json
import math
from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest

from backend.risk.ranking import (
    ASSET_MULTIPLIER,
    SEVERITY_WEIGHT,
    RiskBreakdown,
    asset_criticality_multiplier,
    confidence_multiplier,
    compute_risk_score,
    correlation_multiplier,
    healthy_score,
    rank_alerts,
    recency_multiplier,
    repeat_dampener,
    risk_level_from_score,
    severity_weight,
)

NOW = datetime(2026, 3, 15, 12, 0, 0, tzinfo=timezone.utc)


# ──────────────────────────────────────────────────────────────────────
# 1. SEVERITY WEIGHTS
# ──────────────────────────────────────────────────────────────────────

class TestSeverityWeights:
    def test_healthy_is_zero(self):
        assert severity_weight("healthy") == 0.00

    def test_info_is_zero(self):
        assert severity_weight("info") == 0.00

    def test_low(self):
        assert severity_weight("low") == 0.05

    def test_medium(self):
        assert severity_weight("medium") == 0.10

    def test_high(self):
        assert severity_weight("high") == 0.30

    def test_critical(self):
        assert severity_weight("critical") == 1.00

    def test_case_insensitive_upper(self):
        assert severity_weight("CRITICAL") == 1.00

    def test_case_insensitive_mixed(self):
        assert severity_weight("HiGh") == 0.30

    def test_case_insensitive_info(self):
        assert severity_weight("INFO") == 0.00

    def test_unknown_returns_0_10(self):
        assert severity_weight("banana") == 0.10

    def test_unknown_returns_0_10_empty_string(self):
        assert severity_weight("") == 0.10

    def test_weights_dict_immutable_values(self):
        expected = {"healthy": 0.00, "info": 0.00, "low": 0.05,
                    "medium": 0.10, "high": 0.30, "critical": 1.00}
        assert SEVERITY_WEIGHT == expected

    def test_all_weights_non_negative(self):
        for w in SEVERITY_WEIGHT.values():
            assert w >= 0.0

    def test_all_weights_are_float(self):
        for w in SEVERITY_WEIGHT.values():
            assert isinstance(w, float)

    def test_healthy_lower_than_low(self):
        assert severity_weight("healthy") < severity_weight("low")

    def test_critical_highest_known(self):
        assert severity_weight("critical") > severity_weight("high")


# ──────────────────────────────────────────────────────────────────────
# 2. CONFIDENCE MULTIPLIER
# ──────────────────────────────────────────────────────────────────────

class TestConfidenceMultiplier:
    def test_below_0_40_returns_0_50(self):
        assert confidence_multiplier(0.00) == 0.50
        assert confidence_multiplier(0.10) == 0.50
        assert confidence_multiplier(0.39) == 0.50

    def test_0_40_to_0_69_returns_0_75(self):
        assert confidence_multiplier(0.40) == 0.75
        assert confidence_multiplier(0.55) == 0.75
        assert confidence_multiplier(0.69) == 0.75

    def test_0_70_to_0_89_returns_1_00(self):
        assert confidence_multiplier(0.70) == 1.00
        assert confidence_multiplier(0.80) == 1.00
        assert confidence_multiplier(0.89) == 1.00

    def test_0_90_to_1_00_returns_1_25(self):
        assert confidence_multiplier(0.90) == 1.25
        assert confidence_multiplier(0.95) == 1.25
        assert confidence_multiplier(1.00) == 1.25

    def test_none_returns_0_50(self):
        assert confidence_multiplier(None) == 0.50

    def test_clamped_above_1(self):
        assert confidence_multiplier(1.50) == 1.25

    def test_clamped_below_0(self):
        assert confidence_multiplier(-0.50) == 0.50

    def test_exactly_0(self):
        assert confidence_multiplier(0) == 0.50

    def test_exactly_0_39(self):
        assert confidence_multiplier(0.39) == 0.50

    def test_exactly_0_40(self):
        assert confidence_multiplier(0.40) == 0.75

    def test_exactly_0_69(self):
        assert confidence_multiplier(0.69) == 0.75

    def test_exactly_0_70(self):
        assert confidence_multiplier(0.70) == 1.00

    def test_exactly_0_89(self):
        assert confidence_multiplier(0.89) == 1.00

    def test_exactly_0_90(self):
        assert confidence_multiplier(0.90) == 1.25


# ──────────────────────────────────────────────────────────────────────
# 3. ASSET CRITICALITY
# ──────────────────────────────────────────────────────────────────────

class TestAssetCriticality:
    def test_low(self):
        assert asset_criticality_multiplier("low") == 0.75

    def test_normal(self):
        assert asset_criticality_multiplier("normal") == 1.00

    def test_important(self):
        assert asset_criticality_multiplier("important") == 1.50

    def test_critical(self):
        assert asset_criticality_multiplier("critical") == 2.00

    def test_none_returns_1_00(self):
        assert asset_criticality_multiplier(None) == 1.00

    def test_empty_string_returns_1_00(self):
        assert asset_criticality_multiplier("") == 1.00

    def test_unknown_returns_1_00(self):
        assert asset_criticality_multiplier("unknown_val") == 1.00

    def test_case_insensitive(self):
        assert asset_criticality_multiplier("CRITICAL") == 2.00
        assert asset_criticality_multiplier("Normal") == 1.00
        assert asset_criticality_multiplier("LOW") == 0.75

    def test_all_multiplier_dict_values(self):
        assert ASSET_MULTIPLIER == {
            "low": 0.75, "normal": 1.00, "important": 1.50, "critical": 2.00,
        }


# ──────────────────────────────────────────────────────────────────────
# 4. CORRELATION MULTIPLIER
# ──────────────────────────────────────────────────────────────────────

class TestCorrelationMultiplier:
    def test_single_returns_1_00(self):
        assert correlation_multiplier(1) == 1.00

    def test_two_returns_1_25(self):
        assert correlation_multiplier(2) == 1.25

    def test_three_returns_1_50(self):
        assert correlation_multiplier(3) == 1.50

    def test_four_returns_1_50(self):
        assert correlation_multiplier(4) == 1.50

    def test_five_returns_2_00(self):
        assert correlation_multiplier(5) == 2.00

    def test_ten_returns_2_00(self):
        assert correlation_multiplier(10) == 2.00

    def test_hundred_returns_2_00(self):
        assert correlation_multiplier(100) == 2.00

    def test_attack_chain_overrides(self):
        assert correlation_multiplier(1, is_attack_chain=True) == 2.50

    def test_attack_chain_overrides_high_count(self):
        assert correlation_multiplier(10, is_attack_chain=True) == 2.50

    def test_attack_chain_ignores_count(self):
        assert correlation_multiplier(100, is_attack_chain=True) == 2.50

    def test_zero_count_returns_1_00(self):
        assert correlation_multiplier(0) == 1.00

    def test_negative_count_returns_1_00(self):
        assert correlation_multiplier(-5) == 1.00


# ──────────────────────────────────────────────────────────────────────
# 5. RECENCY DECAY
# ──────────────────────────────────────────────────────────────────────

class TestRecencyDecay:
    def test_none_returns_0_50(self):
        assert recency_multiplier(None, NOW) == 0.50

    def test_just_now_0min(self):
        assert recency_multiplier(NOW, NOW) == 1.00

    def test_1min(self):
        assert recency_multiplier(NOW - timedelta(minutes=1), NOW) == 1.00

    def test_15min_boundary(self):
        assert recency_multiplier(NOW - timedelta(minutes=15), NOW) == 1.00

    def test_16min(self):
        assert recency_multiplier(NOW - timedelta(minutes=16), NOW) == 0.90

    def test_30min(self):
        assert recency_multiplier(NOW - timedelta(minutes=30), NOW) == 0.90

    def test_60min_boundary(self):
        assert recency_multiplier(NOW - timedelta(minutes=60), NOW) == 0.90

    def test_61min(self):
        assert recency_multiplier(NOW - timedelta(minutes=61), NOW) == 0.70

    def test_2h(self):
        assert recency_multiplier(NOW - timedelta(hours=2), NOW) == 0.70

    def test_6h_boundary(self):
        assert recency_multiplier(NOW - timedelta(hours=6), NOW) == 0.70

    def test_6h_1min(self):
        assert recency_multiplier(NOW - timedelta(hours=6, minutes=1), NOW) == 0.50

    def test_12h(self):
        assert recency_multiplier(NOW - timedelta(hours=12), NOW) == 0.50

    def test_24h_boundary(self):
        assert recency_multiplier(NOW - timedelta(hours=24), NOW) == 0.50

    def test_24h_1min(self):
        assert recency_multiplier(NOW - timedelta(hours=24, minutes=1), NOW) == 0.25

    def test_2d(self):
        assert recency_multiplier(NOW - timedelta(days=2), NOW) == 0.25

    def test_3d_boundary(self):
        assert recency_multiplier(NOW - timedelta(days=3), NOW) == 0.25

    def test_3d_1min(self):
        assert recency_multiplier(NOW - timedelta(days=3, minutes=1), NOW) == 0.10

    def test_7d(self):
        assert recency_multiplier(NOW - timedelta(days=7), NOW) == 0.10

    def test_30d(self):
        assert recency_multiplier(NOW - timedelta(days=30), NOW) == 0.10

    def test_future_alert(self):
        future = NOW + timedelta(hours=1)
        assert recency_multiplier(future, NOW) == 1.00

    def test_naive_datetime_treated_as_utc(self):
        naive = datetime(2026, 3, 15, 11, 55, 0)
        assert recency_multiplier(naive, NOW) == 1.00

    def test_boundary_0_minutes(self):
        assert recency_multiplier(NOW, NOW) == 1.00

    def test_boundary_14min59sec(self):
        assert recency_multiplier(NOW - timedelta(minutes=14, seconds=59), NOW) == 1.00

    def test_boundary_15min1sec(self):
        assert recency_multiplier(NOW - timedelta(minutes=15, seconds=1), NOW) == 0.90

    def test_boundary_59min59sec(self):
        assert recency_multiplier(NOW - timedelta(minutes=59, seconds=59), NOW) == 0.90

    def test_boundary_60min1sec(self):
        assert recency_multiplier(NOW - timedelta(minutes=60, seconds=1), NOW) == 0.70

    def test_boundary_5h59min59sec(self):
        assert recency_multiplier(NOW - timedelta(hours=5, minutes=59, seconds=59), NOW) == 0.70

    def test_boundary_6h1sec(self):
        assert recency_multiplier(NOW - timedelta(hours=6, seconds=1), NOW) == 0.50

    def test_boundary_23h59min59sec(self):
        assert recency_multiplier(NOW - timedelta(hours=23, minutes=59, seconds=59), NOW) == 0.50

    def test_boundary_24h1sec(self):
        assert recency_multiplier(NOW - timedelta(hours=24, seconds=1), NOW) == 0.25

    def test_boundary_2d23h59min59sec(self):
        assert recency_multiplier(NOW - timedelta(days=2, hours=23, minutes=59, seconds=59), NOW) == 0.25

    def test_boundary_3d1sec(self):
        assert recency_multiplier(NOW - timedelta(days=3, seconds=1), NOW) == 0.10

    def test_all_multipliers_valid(self):
        """All decay values must be one of the spec'd tiers."""
        valid = {1.00, 0.90, 0.70, 0.50, 0.25, 0.10}
        for delta in [0, 1, 15, 16, 60, 61, 360, 361, 1440, 1441, 4320, 4321]:
            m = recency_multiplier(NOW - timedelta(minutes=delta), NOW)
            assert m in valid, f"minutes={delta} got {m}"


# ──────────────────────────────────────────────────────────────────────
# 6. CORE FORMULA
# ──────────────────────────────────────────────────────────────────────

class TestCoreFormula:
    def test_spec_example(self):
        """high(0.30) × 0.95conf(1.25) × critical(2.00) × 3alerts(1.50) × 8min(1.00) = 1.125"""
        bd = compute_risk_score(
            severity="high",
            confidence=0.95,
            asset_criticality="critical",
            correlated_alerts=3,
            last_seen=NOW - timedelta(minutes=8),
            now=NOW,
        )
        assert bd.severity_weight == 0.30
        assert bd.confidence_multiplier == 1.25
        assert bd.asset_multiplier == 2.00
        assert bd.correlation_multiplier == 1.50
        assert bd.recency_multiplier == 1.00
        assert bd.repeat_dampener == 1.00
        assert bd.risk_score == 1.125

    def test_all_defaults(self):
        bd = compute_risk_score(severity="medium", now=NOW)
        assert bd.severity_weight == 0.10
        assert bd.confidence_multiplier == 0.50
        assert bd.asset_multiplier == 1.00
        assert bd.correlation_multiplier == 1.00
        assert bd.recency_multiplier == 1.00
        assert bd.repeat_dampener == 1.00
        assert bd.risk_score == 0.050

    def test_healthy_always_zero(self):
        bd = compute_risk_score(severity="healthy", now=NOW)
        assert bd.risk_score == 0.0

    def test_info_always_zero(self):
        bd = compute_risk_score(severity="info", now=NOW)
        assert bd.risk_score == 0.0

    def test_critical_full_formula(self):
        bd = compute_risk_score(
            severity="critical",
            confidence=1.00,
            asset_criticality="critical",
            correlated_alerts=5,
            last_seen=NOW,
            occurrence=1,
            now=NOW,
        )
        # 1.00 × 1.25 × 2.00 × 2.00 × 1.00 × 1.00 = 5.0
        assert bd.risk_score == 5.0

    def test_minimum_nonzero_score(self):
        bd = compute_risk_score(
            severity="low",
            confidence=0.01,
            last_seen=NOW - timedelta(days=7),
            now=NOW,
        )
        # 0.05 × 0.50 × 1.00 × 1.00 × 0.10 × 1.00 = 0.0025 → 0.003
        assert bd.risk_score == 0.003

    def test_score_always_non_negative(self):
        bd = compute_risk_score(severity="healthy", now=NOW)
        assert bd.risk_score >= 0.0

    def test_score_is_rounded_to_3_places(self):
        bd = compute_risk_score(
            severity="high",
            confidence=0.95,
            asset_criticality="critical",
            correlated_alerts=3,
            last_seen=NOW - timedelta(minutes=8),
            now=NOW,
        )
        assert bd.risk_score == round(bd.risk_score, 3)

    def test_raw_multiplication_matches(self):
        sw, cm, acm, crm, rm, rd = 0.30, 0.75, 1.50, 1.50, 0.90, 0.75
        expected = round(sw * cm * acm * crm * rm * rd, 3)
        bd = compute_risk_score(
            severity="high",
            confidence=0.55,
            asset_criticality="important",
            correlated_alerts=3,
            last_seen=NOW - timedelta(minutes=30),
            occurrence=3,
            now=NOW,
        )
        assert bd.risk_score == expected


# ──────────────────────────────────────────────────────────────────────
# 7. REPEAT DAMPENING
# ──────────────────────────────────────────────────────────────────────

class TestRepeatDampening:
    def test_first_occurrence(self):
        assert repeat_dampener(1) == 1.00

    def test_second(self):
        assert repeat_dampener(2) == 0.75

    def test_fifth(self):
        assert repeat_dampener(5) == 0.75

    def test_sixth(self):
        assert repeat_dampener(6) == 0.50

    def test_tenth(self):
        assert repeat_dampener(10) == 0.50

    def test_eleventh(self):
        assert repeat_dampener(11) == 0.25

    def test_hundredth(self):
        assert repeat_dampener(100) == 0.25

    def test_one_thousandth(self):
        assert repeat_dampener(1000) == 0.25

    def test_zero_occurrence_treated_as_first(self):
        assert repeat_dampener(0) == 1.00

    def test_negative_treated_as_first(self):
        assert repeat_dampener(-5) == 1.00

    def test_100_low_does_not_beat_1_critical(self):
        low = compute_risk_score(severity="low", now=NOW, occurrence=100)
        crit = compute_risk_score(severity="critical", now=NOW, occurrence=1)
        # low ×100occ → 0.05 × 0.50 × 1.00 × 1.00 × 1.00 × 0.25 = 0.00625
        # critical ×1occ → 1.00 × 0.50 × 1.00 × 1.00 × 1.00 × 1.00 = 0.500
        assert crit.risk_score > low.risk_score


# ──────────────────────────────────────────────────────────────────────
# 8. RISK LEVELS FROM SCORE
# ──────────────────────────────────────────────────────────────────────

class TestRiskLevelFromScore:
    def test_zero_is_healthy(self):
        assert risk_level_from_score(0.0) == "HEALTHY"

    def test_low_range(self):
        assert risk_level_from_score(0.01) == "LOW"
        assert risk_level_from_score(0.29) == "LOW"

    def test_medium_range(self):
        assert risk_level_from_score(0.30) == "MEDIUM"
        assert risk_level_from_score(0.99) == "MEDIUM"

    def test_high_range(self):
        assert risk_level_from_score(1.0) == "HIGH"
        assert risk_level_from_score(1.99) == "HIGH"

    def test_critical_range(self):
        assert risk_level_from_score(2.0) == "CRITICAL"
        assert risk_level_from_score(5.0) == "CRITICAL"

    def test_negative_is_healthy(self):
        assert risk_level_from_score(-1.0) == "HEALTHY"


# ──────────────────────────────────────────────────────────────────────
# 9. RANKING ORDER
# ──────────────────────────────────────────────────────────────────────

class TestRankingOrder:
    def _alert(self, severity, confidence=0.8, occ=1, chain=False, corr=1):
        return {
            "severity": severity,
            "confidence": confidence,
            "last_seen": NOW - timedelta(minutes=5),
            "occurrence": occ,
            "is_attack_chain": chain,
            "correlated_alerts": corr,
        }

    def test_critical_above_high(self):
        alerts = [self._alert("high"), self._alert("critical")]
        ranked = rank_alerts(alerts, NOW)
        assert ranked[0]["severity"] == "critical"

    def test_high_above_medium(self):
        alerts = [self._alert("medium"), self._alert("high")]
        ranked = rank_alerts(alerts, NOW)
        assert ranked[0]["severity"] == "high"

    def test_same_severity_higher_confidence_first(self):
        a = self._alert("high", confidence=0.50)
        b = self._alert("high", confidence=0.95)
        ranked = rank_alerts([a, b], NOW)
        assert ranked[0]["confidence"] == 0.95

    def test_same_severity_same_confidence_more_correlated_first(self):
        a = self._alert("high", corr=1)
        b = self._alert("high", corr=5)
        ranked = rank_alerts([a, b], NOW)
        assert ranked[0]["correlated_alerts"] == 5

    def test_attack_chain_first(self):
        a = self._alert("high", chain=False)
        b = self._alert("high", chain=True)
        ranked = rank_alerts([a, b], NOW)
        assert ranked[0]["is_attack_chain"] is True

    def test_higher_score_comes_first(self):
        alerts = [
            self._alert("low", confidence=0.99),
            self._alert("critical", confidence=0.50),
        ]
        ranked = rank_alerts(alerts, NOW)
        assert ranked[0]["severity"] == "critical"
        assert ranked[1]["severity"] == "low"

    def test_all_healthy_stay_healthy(self):
        alerts = [
            self._alert("healthy"),
            self._alert("healthy"),
        ]
        ranked = rank_alerts(alerts, NOW)
        assert all(a["risk_level"] == "HEALTHY" for a in ranked)

    def test_sorted_descending(self):
        alerts = [
            self._alert("low"),
            self._alert("critical"),
            self._alert("medium"),
            self._alert("high"),
        ]
        ranked = rank_alerts(alerts, NOW)
        scores = [a["risk_score"] for a in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_ten_alerts_ranked_correctly(self):
        severities = ["low", "medium", "high", "critical", "info",
                      "low", "medium", "high", "critical", "healthy"]
        alerts = [self._alert(s) for s in severities]
        ranked = rank_alerts(alerts, NOW)
        scores = [a["risk_score"] for a in ranked]
        assert scores == sorted(scores, reverse=True)


# ──────────────────────────────────────────────────────────────────────
# 10. EXPLAINABILITY (RiskBreakdown)
# ──────────────────────────────────────────────────────────────────────

class TestExplainability:
    def _bd(self):
        return compute_risk_score(
            severity="high",
            confidence=0.90,
            asset_criticality="critical",
            correlated_alerts=3,
            last_seen=NOW - timedelta(minutes=8),
            now=NOW,
        )

    def test_has_all_fields(self):
        bd = self._bd()
        expected_fields = {
            "risk_score", "severity", "severity_weight", "confidence",
            "confidence_multiplier", "asset_criticality", "asset_multiplier",
            "correlation_level", "correlated_alerts", "correlation_multiplier",
            "is_attack_chain", "recency_minutes", "recency_multiplier",
            "occurrence", "repeat_dampener", "risk_level",
        }
        actual = {f.name for f in bd.__dataclass_fields__.values()}
        assert expected_fields == actual

    def test_explanation_returns_string(self):
        text = self._bd().explanation()
        assert isinstance(text, str)
        assert len(text) > 0

    def test_explanation_contains_severity(self):
        text = self._bd().explanation()
        assert "HIGH" in text

    def test_explanation_contains_risk_score(self):
        text = self._bd().explanation()
        assert "Risk Score" in text

    def test_explanation_contains_confidence(self):
        text = self._bd().explanation()
        assert "Confidence" in text

    def test_to_dict_returns_dict(self):
        d = self._bd().to_dict()
        assert isinstance(d, dict)

    def test_to_dict_json_serializable(self):
        d = self._bd().to_dict()
        json_str = json.dumps(d)
        assert isinstance(json_str, str)
        restored = json.loads(json_str)
        assert restored["risk_score"] == d["risk_score"]

    def test_to_dict_has_all_keys(self):
        d = self._bd().to_dict()
        assert "risk_score" in d
        assert "severity" in d
        assert "severity_weight" in d
        assert "confidence" in d
        assert "recency_multiplier" in d
        assert "risk_level" in d

    def test_to_dict_values_match_fields(self):
        bd = self._bd()
        d = bd.to_dict()
        assert d["risk_score"] == bd.risk_score
        assert d["severity"] == bd.severity
        assert d["severity_weight"] == bd.severity_weight

    def test_explanation_repeat_line_present(self):
        bd = compute_risk_score(
            severity="medium", occurrence=3, now=NOW,
        )
        text = bd.explanation()
        assert "Repeat" in text

    def test_explanation_recency_hours_format(self):
        bd = compute_risk_score(
            severity="medium",
            last_seen=NOW - timedelta(hours=2),
            now=NOW,
        )
        text = bd.explanation()
        assert "hours" in text

    def test_explanation_recency_minutes_format(self):
        bd = compute_risk_score(
            severity="medium",
            last_seen=NOW - timedelta(minutes=10),
            now=NOW,
        )
        text = bd.explanation()
        assert "minutes" in text

    def test_explanation_attack_chain_label(self):
        bd = compute_risk_score(
            severity="medium",
            correlated_alerts=3,
            is_attack_chain=True,
            now=NOW,
        )
        text = bd.explanation()
        assert "Attack chain" in text

    def test_explanation_single_alert_label(self):
        bd = compute_risk_score(severity="medium", now=NOW)
        text = bd.explanation()
        assert "1 alert" in text

    def test_explanation_plurals(self):
        bd = compute_risk_score(
            severity="medium", correlated_alerts=5, now=NOW,
        )
        text = bd.explanation()
        assert "alerts" in text


# ──────────────────────────────────────────────────────────────────────
# 11. HEALTHY STATE
# ──────────────────────────────────────────────────────────────────────

class TestHealthyState:
    def test_healthy_score_returns_zero(self):
        bd = healthy_score()
        assert bd.risk_score == 0.0

    def test_healthy_level(self):
        bd = healthy_score()
        assert bd.risk_level == "HEALTHY"

    def test_healthy_severity_weight_zero(self):
        bd = healthy_score()
        assert bd.severity_weight == 0.0

    def test_healthy_severity_string(self):
        bd = healthy_score()
        assert bd.severity == "healthy"

    def test_healthy_to_dict(self):
        d = healthy_score().to_dict()
        assert d["risk_score"] == 0.0
        assert d["risk_level"] == "HEALTHY"

    def test_healthy_json_serializable(self):
        d = healthy_score().to_dict()
        json.dumps(d)

    def test_healthy_explanation(self):
        text = healthy_score().explanation()
        assert isinstance(text, str)


# ──────────────────────────────────────────────────────────────────────
# 12. DATA INTEGRITY
# ──────────────────────────────────────────────────────────────────────

class TestDataIntegrity:
    def test_severity_preserved_separately(self):
        bd = compute_risk_score(severity="high", now=NOW)
        assert bd.severity == "high"
        assert bd.severity_weight == 0.30
        assert bd.severity != bd.severity_weight

    def test_asset_criticality_preserved(self):
        bd = compute_risk_score(
            severity="medium", asset_criticality="critical", now=NOW,
        )
        assert bd.asset_criticality == "critical"
        assert bd.asset_multiplier == 2.00

    def test_confidence_preserved(self):
        bd = compute_risk_score(severity="medium", confidence=0.75, now=NOW)
        assert bd.confidence == 0.75

    def test_correlated_alerts_preserved(self):
        bd = compute_risk_score(
            severity="medium", correlated_alerts=4, now=NOW,
        )
        assert bd.correlated_alerts == 4

    def test_occurrence_preserved(self):
        bd = compute_risk_score(severity="medium", occurrence=7, now=NOW)
        assert bd.occurrence == 7

    def test_is_attack_chain_preserved(self):
        bd = compute_risk_score(
            severity="medium", is_attack_chain=True, now=NOW,
        )
        assert bd.is_attack_chain is True

    def test_correlation_level_labels(self):
        bd1 = compute_risk_score(severity="low", now=NOW)
        assert bd1.correlation_level == "single"
        bd2 = compute_risk_score(severity="low", correlated_alerts=2, now=NOW)
        assert bd2.correlation_level == "2"
        bd3 = compute_risk_score(severity="low", correlated_alerts=3, now=NOW)
        assert bd3.correlation_level == "3-4"
        bd4 = compute_risk_score(severity="low", correlated_alerts=5, now=NOW)
        assert bd4.correlation_level == "5+"
        bd5 = compute_risk_score(
            severity="low", is_attack_chain=True, now=NOW,
        )
        assert bd5.correlation_level == "attack_chain"

    def test_clamped_occurrence(self):
        bd = compute_risk_score(severity="medium", occurrence=-5, now=NOW)
        assert bd.occurrence >= 1

    def test_clamped_correlated_alerts(self):
        bd = compute_risk_score(
            severity="medium", correlated_alerts=-3, now=NOW,
        )
        assert bd.correlated_alerts >= 1


# ──────────────────────────────────────────────────────────────────────
# 13. EDGE CASES
# ──────────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_no_nan_in_score(self):
        bd = compute_risk_score(
            severity="critical",
            confidence=0.0,
            last_seen=None,
            now=NOW,
        )
        assert not math.isnan(bd.risk_score)

    def test_no_infinite_in_score(self):
        bd = compute_risk_score(
            severity="critical",
            confidence=1.0,
            asset_criticality="critical",
            correlated_alerts=100,
            last_seen=NOW,
            now=NOW,
        )
        assert not math.isinf(bd.risk_score)

    def test_no_negative_score(self):
        bd = compute_risk_score(severity="info", now=NOW)
        assert bd.risk_score >= 0.0

    def test_missing_confidence(self):
        bd = compute_risk_score(severity="high", confidence=None, now=NOW)
        assert bd.confidence == 0.0
        assert bd.confidence_multiplier == 0.50

    def test_missing_asset(self):
        bd = compute_risk_score(severity="high", asset_criticality=None, now=NOW)
        assert bd.asset_criticality == "normal"
        assert bd.asset_multiplier == 1.00

    def test_old_alerts(self):
        bd = compute_risk_score(
            severity="critical",
            last_seen=NOW - timedelta(days=365),
            now=NOW,
        )
        assert bd.recency_multiplier == 0.10
        assert bd.risk_score > 0.0

    def test_very_high_confidence(self):
        bd = compute_risk_score(severity="medium", confidence=0.9999, now=NOW)
        assert bd.confidence_multiplier == 1.25

    def test_confidence_exactly_boundary_0(self):
        bd = compute_risk_score(severity="medium", confidence=0.0, now=NOW)
        assert bd.confidence_multiplier == 0.50

    def test_confidence_exactly_1(self):
        bd = compute_risk_score(severity="medium", confidence=1.0, now=NOW)
        assert bd.confidence_multiplier == 1.25

    def test_risk_score_type_is_float(self):
        bd = compute_risk_score(severity="critical", now=NOW)
        assert isinstance(bd.risk_score, float)

    def test_all_multiplier_fields_are_float(self):
        bd = compute_risk_score(
            severity="high",
            confidence=0.85,
            asset_criticality="important",
            correlated_alerts=4,
            last_seen=NOW - timedelta(hours=1),
            occurrence=3,
            now=NOW,
        )
        assert isinstance(bd.severity_weight, float)
        assert isinstance(bd.confidence_multiplier, float)
        assert isinstance(bd.asset_multiplier, float)
        assert isinstance(bd.correlation_multiplier, float)
        assert isinstance(bd.recency_multiplier, float)
        assert isinstance(bd.repeat_dampener, float)

    def test_very_many_correlated_alerts(self):
        bd = compute_risk_score(
            severity="low", correlated_alerts=9999, now=NOW,
        )
        assert bd.correlation_multiplier == 2.00
        assert bd.risk_score >= 0.0

    def test_zero_occurrence_clamped(self):
        bd = compute_risk_score(severity="medium", occurrence=0, now=NOW)
        assert bd.repeat_dampener == 1.00

    def test_risk_level_matches_score(self):
        for sev, conf, asset, corr, occ in [
            ("critical", 1.0, "critical", 5, 1),
            ("high", 0.9, "important", 3, 1),
            ("medium", 0.7, "normal", 1, 1),
            ("low", 0.5, "low", 1, 1),
            ("healthy", None, None, 1, 1),
        ]:
            bd = compute_risk_score(
                severity=sev,
                confidence=conf,
                asset_criticality=asset,
                correlated_alerts=corr,
                occurrence=occ,
                last_seen=NOW,
                now=NOW,
            )
            assert bd.risk_level == risk_level_from_score(bd.risk_score)

    def test_rank_alerts_empty_list(self):
        ranked = rank_alerts([], NOW)
        assert ranked == []

    def test_rank_alerts_single_alert(self):
        alerts = [{
            "severity": "medium",
            "confidence": 0.8,
            "last_seen": NOW - timedelta(minutes=5),
        }]
        ranked = rank_alerts(alerts, NOW)
        assert len(ranked) == 1
        assert ranked[0]["risk_score"] >= 0.0

    def test_rank_alerts_missing_fields(self):
        alerts = [{"severity": "high"}]
        ranked = rank_alerts(alerts, NOW)
        assert len(ranked) == 1
        assert ranked[0]["risk_score"] >= 0.0

    def test_rank_alerts_string_timestamps(self):
        alerts = [{
            "severity": "medium",
            "confidence": 0.7,
            "updated_at": "2026-03-15T11:50:00Z",
        }]
        ranked = rank_alerts(alerts, NOW)
        assert len(ranked) == 1

    def test_rank_alerts_invalid_string_timestamp(self):
        alerts = [{
            "severity": "medium",
            "confidence": 0.7,
            "updated_at": "not-a-date",
        }]
        ranked = rank_alerts(alerts, NOW)
        assert len(ranked) == 1

    def test_rank_alerts_preserves_original_dict(self):
        alerts = [{
            "severity": "high",
            "confidence": 0.9,
            "last_seen": NOW - timedelta(minutes=5),
            "custom_field": "hello",
        }]
        ranked = rank_alerts(alerts, NOW)
        assert ranked[0]["custom_field"] == "hello"

    def test_rank_alerts_adds_risk_fields(self):
        alerts = [{
            "severity": "high",
            "confidence": 0.9,
            "last_seen": NOW - timedelta(minutes=5),
        }]
        ranked = rank_alerts(alerts, NOW)
        assert "risk_score" in ranked[0]
        assert "risk_level" in ranked[0]
        assert "risk_breakdown" in ranked[0]

    def test_rank_alerts_breakdown_is_dict(self):
        alerts = [{
            "severity": "medium",
            "confidence": 0.8,
            "last_seen": NOW - timedelta(minutes=5),
        }]
        ranked = rank_alerts(alerts, NOW)
        assert isinstance(ranked[0]["risk_breakdown"], dict)


# ──────────────────────────────────────────────────────────────────────
# 14. COMBINED / INTEGRATION
# ──────────────────────────────────────────────────────────────────────

class TestCombinedIntegration:
    def test_critical_attack_chain_recent(self):
        bd = compute_risk_score(
            severity="critical",
            confidence=1.0,
            asset_criticality="critical",
            correlated_alerts=10,
            is_attack_chain=True,
            last_seen=NOW - timedelta(minutes=1),
            occurrence=1,
            now=NOW,
        )
        # 1.00 × 1.25 × 2.00 × 2.50 × 1.00 × 1.00 = 6.25
        assert bd.risk_score == 6.25
        assert bd.risk_level == "CRITICAL"

    def test_low_info_old_many_repeats(self):
        bd = compute_risk_score(
            severity="info",
            confidence=0.10,
            asset_criticality="low",
            last_seen=NOW - timedelta(days=10),
            occurrence=50,
            now=NOW,
        )
        assert bd.risk_score == 0.0
        assert bd.risk_level == "HEALTHY"

    def test_medium_no_confidence_recent(self):
        bd = compute_risk_score(
            severity="medium",
            last_seen=NOW - timedelta(minutes=3),
            now=NOW,
        )
        # 0.10 × 0.50 × 1.00 × 1.00 × 1.00 × 1.00 = 0.050
        assert bd.risk_score == 0.050

    def test_flood_dampening(self):
        first = compute_risk_score(severity="high", occurrence=1, now=NOW)
        flood = compute_risk_score(severity="high", occurrence=20, now=NOW)
        assert flood.risk_score < first.risk_score

    def test_batch_ranking_mixed(self):
        alerts = [
            {"severity": "critical", "confidence": 0.9,
             "last_seen": NOW - timedelta(minutes=2)},
            {"severity": "low", "confidence": 0.3,
             "last_seen": NOW - timedelta(days=5)},
            {"severity": "high", "confidence": 0.8,
             "asset_criticality": "critical",
             "correlated_alerts": 5,
             "last_seen": NOW - timedelta(minutes=10)},
        ]
        ranked = rank_alerts(alerts, NOW)
        assert ranked[0]["severity"] == "critical"
        assert ranked[-1]["severity"] == "low"
        scores = [a["risk_score"] for a in ranked]
        assert scores == sorted(scores, reverse=True)
