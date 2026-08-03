"""Tests for the Evaluation Framework (Upgrade Module 10)."""
from __future__ import annotations

import pytest

from backend.database.models import EvaluationRun
from backend.evaluation.evaluator import SCENARIOS, _metrics, run_evaluation


def test_metrics_perfect_detection():
    m = _metrics(tp=10, fp=0, tn=5, fn=0)
    assert m["accuracy"] == 1.0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0


def test_metrics_guard_against_zero_division():
    m = _metrics(tp=0, fp=0, tn=5, fn=0)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    m2 = _metrics(tp=0, fp=0, tn=0, fn=0)
    assert m2["accuracy"] == 1.0


def test_metrics_mixed_case():
    m = _metrics(tp=8, fp=2, tn=18, fn=2)
    assert m["accuracy"] == pytest.approx(26 / 30, abs=0.001)
    assert m["precision"] == pytest.approx(0.8, abs=0.001)
    assert m["recall"] == pytest.approx(0.8, abs=0.001)
    assert m["f1_score"] == pytest.approx(0.8, abs=0.001)
    assert m["false_positive_rate"] == pytest.approx(2 / 20, abs=0.001)


def test_run_evaluation_detects_all_attack_scenarios(db):
    result = run_evaluation(db, with_ml=False)
    assert len(result["runs"]) == len(SCENARIOS)
    overall = result["overall"]
    # Attack scenarios must be detected (recall >= 0.5 overall), baseline clean.
    assert overall["true_positives"] > 0
    assert overall["recall"] > 0.5
    assert overall["false_positive_rate"] < 0.5

    by_scenario = {r["scenario"]: r for r in result["runs"]}
    for name in ("brute_force", "powershell", "privilege_escalation", "persistence", "port_scan"):
        assert by_scenario[name]["true_positives"] > 0, f"{name} produced no true positives"
    assert by_scenario["baseline"]["false_positives"] < 5, "baseline produced too many FPs"

    # Persisted to the production DB.
    runs = db.query(EvaluationRun).all()
    assert len(runs) >= len(SCENARIOS) + 1
