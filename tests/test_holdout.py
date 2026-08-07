"""Tests for the Hold-out Evaluation Framework (external validity)."""
from __future__ import annotations

import pytest

from backend.database.models import EvaluationRun
from backend.evaluation.holdout import (
    HOLDOUT_SCENARIOS,
    SCENARIO_RULE,
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
    """Rule or ML must catch every hold-out attack the system never trained on."""
    result = run_holdout_evaluation(db, with_ml=True, use_real_baseline=False)

    assert result["methodology"]["training_split"] == TRAIN_SCENARIOS
    assert result["methodology"]["holdout_split"] == HOLDOUT_SCENARIOS
    assert result["methodology"]["train_test_separation"]

    by_scenario = {s["scenario"]: s for s in result["per_scenario"]}
    for scenario in HOLDOUT_SCENARIOS:
        assert scenario in by_scenario, f"missing scenario {scenario}"
        stats = by_scenario[scenario]
        covered = stats["rule_detected"] or stats["ml_tp"] > 0 or stats["hybrid_tp"] > 0
        assert covered, f"{scenario} unseen by every layer"

    # Every scenario the RULE layer claims must actually fire.
    for scenario, rule in SCENARIO_RULE.items():
        assert by_scenario[scenario]["rule_detected"], f"rule {rule} did not fire on {scenario}"

    rule = result["rule_layer"]
    assert rule["true_positives"] > 0
    assert rule["false_positives"] == 0
    assert rule["precision"] == 1.0

    # ML layer must independently catch some *unseen* behavioral attacks and
    # stay within the label-free false-alarm budget on the benign baseline.
    ml = result["ml_layer"]
    assert ml is not None
    assert ml["true_positives"] > 0
    assert ml["recall"] >= 0.4
    assert ml["false_positive_rate"] <= 0.05

    hybrid = result["hybrid_layer"]
    assert hybrid["true_positives"] > 0
    assert hybrid["recall"] >= 0.85
    assert hybrid["false_positive_rate"] <= 0.05

    # Persisted to the production DB.
    runs = db.query(EvaluationRun).filter(EvaluationRun.scenario.like("holdout:%")).all()
    assert len(runs) >= 3  # rule, ml, hybrid

    # FN root-cause report: entries only for scenarios no layer detected, and
    # every entry carries a remediation hint.
    fn_report = result["false_negative_report"]
    covered_scenarios = {s["scenario"] for s in result["per_scenario"] if s["hybrid_tp"] > 0}
    assert all(e["scenario"] not in covered_scenarios for e in fn_report)
    for entry in fn_report:
        assert entry["root_cause"] in ("rule-missed", "ml-missed", "both-layers-missed")
        assert entry["remediation"]


def test_holdout_with_real_baseline(db):
    """Run with real host telemetry as negatives (external validity)."""
    result = run_holdout_evaluation(db, with_ml=False, use_real_baseline=True)
    assert result["methodology"]["negative_class"] == "real-host-telemetry"
    assert result["methodology"]["n_baseline_records"] > 0
    assert result["rule_layer"]["false_positives"] == 0


def test_holdout_domain_randomization_is_seeded_and_stable(db):
    """Randomized runs must be reproducible (same seed) and still detect."""
    a = run_holdout_evaluation(db, with_ml=False, use_real_baseline=False, randomize=True, seed=42)
    b = run_holdout_evaluation(db, with_ml=False, use_real_baseline=False, randomize=True, seed=42)

    assert a["methodology"]["randomization"] == "seeded-domain-randomization"
    assert a["methodology"]["randomization_seed"] == 42
    # Same seed -> identical per-scenario outcome.
    assert [r["hybrid_tp"] for r in a["per_scenario"]] == [r["hybrid_tp"] for r in b["per_scenario"]]
    # Randomization must not break rule-layer detection of hold-out scenarios.
    for scenario in HOLDOUT_SCENARIOS:
        stats = next(s for s in a["per_scenario"] if s["scenario"] == scenario)
        assert stats["rule_detected"] or stats["hybrid_tp"] > 0, f"{scenario} missed under randomization"
