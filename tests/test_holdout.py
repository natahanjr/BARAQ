"""Tests for the Hold-out Evaluation Framework (external validity)."""
from __future__ import annotations

import pytest

from backend.database.models import EvaluationRun
from backend.evaluation.holdout import (
    HOLDOUT_SCENARIOS,
    TRAIN_SCENARIOS,
    _metrics,
    run_holdout_evaluation,
)


def test_holdout_splits_are_disjoint():
    assert not set(TRAIN_SCENARIOS) & set(HOLDOUT_SCENARIOS)
    assert len(HOLDOUT_SCENARIOS) >= 5


def test_metrics_helper():
    m = _metrics(tp=8, fp=2, tn=18, fn=2)
    assert m["accuracy"] == pytest.approx(26 / 30, abs=0.001)
    assert m["precision"] == pytest.approx(0.8, abs=0.001)
    assert m["recall"] == pytest.approx(0.8, abs=0.001)
    assert m["f1_score"] == pytest.approx(0.8, abs=0.001)


def test_holdout_detects_unseen_attacks(db):
    """Rules must detect hold-out attacks the system never trained on."""
    result = run_holdout_evaluation(db, with_ml=False, use_real_baseline=False)

    assert result["methodology"]["training_split"] == TRAIN_SCENARIOS
    assert result["methodology"]["holdout_split"] == HOLDOUT_SCENARIOS
    assert result["methodology"]["train_test_separation"]

    by_scenario = {s["scenario"]: s for s in result["per_scenario"]}
    for scenario in HOLDOUT_SCENARIOS:
        assert scenario in by_scenario, f"missing scenario {scenario}"
        assert by_scenario[scenario]["rule_detected"], f"{scenario} not detected"

    rule = result["rule_layer"]
    assert rule["true_positives"] > 0
    assert rule["recall"] > 0.8
    assert rule["false_positives"] == 0
    assert rule["precision"] == 1.0

    # Persisted to the production DB.
    runs = db.query(EvaluationRun).filter(EvaluationRun.scenario.like("holdout:%")).all()
    assert len(runs) >= 3  # rule, ml (skipped?), hybrid -> rule + hybrid minimum


def test_holdout_with_real_baseline(db):
    """Run with real host telemetry as negatives (external validity)."""
    result = run_holdout_evaluation(db, with_ml=False, use_real_baseline=True)
    assert result["methodology"]["negative_class"] == "real-host-telemetry"
    assert result["methodology"]["n_baseline_records"] > 0
    assert result["rule_layer"]["false_positives"] == 0
