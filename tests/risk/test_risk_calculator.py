"""Phase 6 calculator tests (spec 6.30-6.34): pure, deterministic, bounded."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from backend.risk.calculator import calculate_risk

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def _factor(
    factor_id: str,
    value: float,
    *,
    origin: str = "DIRECT",
    created_at: datetime = T0,
    expires_at: datetime | None = None,
    weight: float = 1.0,
    reason: str = "test",
) -> dict:
    return {
        "factor_id": factor_id,
        "factor_type": "TEST",
        "source_type": "test",
        "source_id": "t1",
        "value": value,
        "weight": weight,
        "origin": origin,
        "created_at": created_at,
        "expires_at": expires_at,
        "reason": reason,
        "evidence": {"test": True},
    }


def test_deterministic_same_inputs_same_output():
    now = T0
    factors = [
        _factor("RF010_BEHAVIOR_GROUP", 10.0),
        _factor("RF009_ALERT_SEVERITY", 6.0),
    ]
    first = calculate_risk(factors, now)
    second = calculate_risk(factors, now)
    assert first.final_score == second.final_score == 16.0
    assert first.factor_contributions == second.factor_contributions


def test_score_is_bounded_at_100():
    now = T0
    factors = [_factor("RF010_BEHAVIOR_GROUP", 100.0) for _ in range(8)]
    calc = calculate_risk(factors, now)
    assert calc.final_score == 100.0


def test_score_is_bounded_at_0():
    now = T0
    factors = [
        _factor("RF010_BEHAVIOR_GROUP", 10.0, created_at=T0 - timedelta(days=400))
    ]
    calc = calculate_risk(factors, now)
    assert calc.final_score == 0.0


def test_decay_adjustments_are_listed():
    now = T0
    calc = calculate_risk(
        [_factor("RF010_BEHAVIOR_GROUP", 10.0, created_at=now - timedelta(hours=24))],
        now,
    )
    assert calc.final_score == pytest.approx(5.0)
    assert len(calc.decay_adjustments) == 1
    adjustment = calc.decay_adjustments[0]
    assert adjustment["original"] == pytest.approx(10.0)
    assert adjustment["decay_factor"] == pytest.approx(0.5)
    assert adjustment["adjustment"] == pytest.approx(5.0)


def test_contextual_added_separately_with_cap():
    now = T0
    calc = calculate_risk(
        [
            _factor("RF010_BEHAVIOR_GROUP", 10.0),
            _factor("RF006_MULTI_STAGE_CORRELATION", 8.0, origin="CONTEXTUAL"),
            _factor("RF006_MULTI_STAGE_CORRELATION", 8.0, origin="CONTEXTUAL"),
        ],
        now,
    )
    assert calc.base_score == pytest.approx(10.0)
    assert calc.final_score == pytest.approx(26.0)
    assert len(calc.propagation_adjustments) == 2


def test_confidence_is_direct_share():
    now = T0
    calc = calculate_risk(
        [
            _factor("RF010_BEHAVIOR_GROUP", 10.0),
            _factor("RF006_MULTI_STAGE_CORRELATION", 8.0, origin="CONTEXTUAL"),
        ],
        now,
    )
    assert calc.confidence == pytest.approx(10.0 / 18.0, abs=1e-4)


def test_expired_factors_still_listed_with_history():
    now = T0
    calc = calculate_risk(
        [_factor("RF010_BEHAVIOR_GROUP", 10.0, expires_at=now - timedelta(hours=1))],
        now,
    )
    assert calc.final_score == 0.0
    assert calc.active_factor_count == 0
    assert calc.expired_factor_count == 1
    assert calc.factor_count == 1
