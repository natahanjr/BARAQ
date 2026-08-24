"""Phase 6 contract tests (spec 6.2, 6.4-6.8, 6.43, 6.44, 6.81, 6.83)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.risk.calculator import (
    calculate_risk,
    decay_factor,
    severity_for,
    state_for,
    thresholds_crossed,
    trend_for,
)
from backend.risk.contract import (
    BANNED_RISK_PHRASES,
    ENTITY_TYPES,
    EVIDENCE_KINDS,
    FACTOR_TYPES,
    ORIGINS,
    RISK_ACTIONS,
    RISK_SEVERITIES,
    RISK_STATES,
    RISK_TRENDS,
    EntityRisk,
    RiskCalculation,
)

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=timezone.utc)


def test_entity_types_are_spec_exact():
    assert set(ENTITY_TYPES) == {
        "HOST", "USER", "ACCOUNT", "SOURCE_IP", "DESTINATION_IP", "PROCESS",
    }


def test_severities_are_spec_exact():
    assert list(RISK_SEVERITIES) == ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_states_are_spec_exact():
    assert list(RISK_STATES) == ["NORMAL", "ELEVATED", "HIGH", "CRITICAL", "STALE"]


def test_trends_and_origins():
    assert list(RISK_TRENDS) == ["RISING", "STABLE", "FALLING", "UNKNOWN"]
    assert list(ORIGINS) == ["DIRECT", "CONTEXTUAL"]


def test_evidence_kinds_are_spec_exact():
    assert list(EVIDENCE_KINDS) == [
        "DETECTION", "ALERT", "BEHAVIOR_GROUP", "CORRELATION_FINDING",
    ]


def test_factor_types_are_spec_exact():
    assert set(FACTOR_TYPES) == {
        "ALERT_SEVERITY", "ALERT_REPETITION", "BEHAVIOR_GROUP", "CORRELATION",
        "LATERAL_MOVEMENT", "EXTERNAL_ACCESS", "CREDENTIAL_ACCESS",
        "PRIVILEGE_ACTIVITY", "PERSISTENCE", "EXECUTION", "DEFENSE_EVASION",
        "RECENCY", "SOURCE_REPUTATION", "ENTITY_SPREAD",
    }


def test_audit_actions_are_spec_exact():
    assert set(RISK_ACTIONS) == {
        "RISK_CREATED", "RISK_UPDATED", "FACTOR_ADDED", "FACTOR_EXPIRED",
        "FACTOR_REMOVED", "RISK_RECALCULATED", "RISK_STATE_CHANGED",
        "RISK_THRESHOLD_CROSSED", "RISK_MODEL_CHANGED", "RISK_CALCULATION_FAILED",
    }


def test_banned_phrases_never_claim_confirmation():
    assert "compromised" in BANNED_RISK_PHRASES
    assert "breached" in BANNED_RISK_PHRASES
    for phrase in BANNED_RISK_PHRASES:
        assert phrase.lower() == phrase


def test_entity_risk_validates():
    base = dict(
        risk_id="ER-000001", entity_type="HOST", entity_id="h1",
        entity_name="h1", score=72.0, severity="HIGH", state="HIGH",
        confidence=1.0, trend="RISING", peak_score=72.0, peak_at=T0,
        first_seen=T0, last_seen=T0, active_factor_count=7,
        evidence_count=2, alert_count=10, group_count=1,
        correlation_count=1, risk_model_version="1.0.0",
    )
    EntityRisk(**base)
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, entity_type="GADGET"))
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, score=101.0))
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, score=-1.0))
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, severity="EXTREME"))
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, state="PENDING"))
    with pytest.raises(ValueError):
        EntityRisk(**dict(base, trend="SIDEWAYS"))


def test_risk_calculation_validates_bounds():
    with pytest.raises(ValueError):
        RiskCalculation(base_score=0.0, final_score=101.0)
    with pytest.raises(ValueError):
        RiskCalculation(base_score=0.0, final_score=-0.01)


def test_severity_mapping_matches_thresholds():
    assert severity_for(0) == "MINIMAL"
    assert severity_for(19) == "MINIMAL"
    assert severity_for(20) == "LOW"
    assert severity_for(39) == "LOW"
    assert severity_for(40) == "MEDIUM"
    assert severity_for(59) == "MEDIUM"
    assert severity_for(60) == "HIGH"
    assert severity_for(79) == "HIGH"
    assert severity_for(80) == "CRITICAL"
    assert severity_for(100) == "CRITICAL"


def test_state_mapping_matches_spec_examples():
    assert state_for(0) == "NORMAL"
    assert state_for(31) == "ELEVATED"
    assert state_for(73) == "HIGH"
    assert state_for(88) == "CRITICAL"


def test_thresholds_crossed_lists_every_severity():
    assert thresholds_crossed(11, 45) == ["LOW", "MEDIUM"]
    assert thresholds_crossed(45, 11) == ["LOW", "MEDIUM"]
    assert thresholds_crossed(11, 88) == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    assert thresholds_crossed(42, 42) == []
    assert thresholds_crossed(39, 40) == ["MEDIUM"]


def test_trend_is_descriptive_only():
    assert trend_for(None, 42.0) == "UNKNOWN"
    assert trend_for(10.0, 42.0) == "RISING"
    assert trend_for(42.0, 42.0) == "STABLE"
    assert trend_for(42.0, 10.0) == "FALLING"
    assert trend_for(40.0, 42.0) == "STABLE"


def test_decay_is_exponential_half_life():
    assert decay_factor(0) == 1.0
    assert decay_factor(24) == pytest.approx(0.5)
    assert decay_factor(48) == pytest.approx(0.25)
    assert decay_factor(1) == pytest.approx(0.5 ** (1 / 24))
    assert decay_factor(-5) == 1.0


def test_calculate_risk_full_decomposition():
    now = T0
    factors = [
        {
            "factor_id": "RF003_LATERAL_MOVEMENT",
            "factor_type": "LATERAL_MOVEMENT",
            "source_type": "behavior_group", "source_id": "g5",
            "value": 18.0, "weight": 1.0, "origin": "DIRECT",
            "created_at": now - timedelta(hours=24), "expires_at": None,
            "reason": "lateral movement", "evidence": {"group_id": "g5"},
        },
        {
            "factor_id": "RF010_BEHAVIOR_GROUP",
            "factor_type": "BEHAVIOR_GROUP",
            "source_type": "behavior_group", "source_id": "g5",
            "value": 10.0, "weight": 1.0, "origin": "DIRECT",
            "created_at": now - timedelta(hours=24), "expires_at": None,
            "reason": "membership", "evidence": {"group_id": "g5"},
        },
        {
            "factor_id": "RF006_MULTI_STAGE_CORRELATION",
            "factor_type": "CORRELATION",
            "source_type": "propagation", "source_id": "user_to_host:u1",
            "value": 8.0, "weight": 1.0, "origin": "CONTEXTUAL",
            "created_at": now, "expires_at": now + timedelta(hours=72),
            "reason": "context", "evidence": {},
            "relationship_type": "user_to_host",
        },
    ]
    calc = calculate_risk(factors, now)
    assert calc.base_score == pytest.approx(14.0)
    assert calc.final_score == pytest.approx(22.0)
    assert len(calc.factor_contributions) == 3
    assert len(calc.propagation_adjustments) == 1
    assert calc.propagation_adjustments[0]["contribution"] == pytest.approx(8.0)
    assert calc.propagation_adjustments[0]["relationship_type"] == "user_to_host"
    assert calc.confidence == pytest.approx(14.0 / 22.0, abs=1e-4)
    assert calc.severity == "LOW"
    assert calc.active_factor_count == 3


def test_calculate_risk_expired_contributes_zero():
    now = T0
    factors = [
        {
            "factor_id": "RF010_BEHAVIOR_GROUP",
            "factor_type": "BEHAVIOR_GROUP",
            "source_type": "behavior_group", "source_id": "g5",
            "value": 10.0, "weight": 1.0, "origin": "DIRECT",
            "created_at": now - timedelta(days=10),
            "expires_at": now - timedelta(hours=1),
            "reason": "membership", "evidence": {},
        }
    ]
    calc = calculate_risk(factors, now)
    assert calc.final_score == 0.0
    assert calc.expired_factor_count == 1
    assert calc.factor_contributions[0]["expired"] is True
    assert calc.factor_contributions[0]["contribution"] == 0.0