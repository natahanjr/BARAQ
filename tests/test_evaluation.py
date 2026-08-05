"""Tests for the Evaluation Framework (live-only mode)."""
from __future__ import annotations

import pytest

from backend.database.models import EvaluationRun
from backend.evaluation.evaluator import _metrics, run_evaluation


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


def test_run_evaluation_live_assessment(db):
    from tests.conftest import run_simulation

    run_simulation(db)
    result = run_evaluation(db, with_ml=False)
    assert result["overall"]["scenario"] == "overall"
    assert result["info"]["events_analyzed"] > 0
    assert result["info"]["findings"] > 0
    assert result["info"]["rules_fired"] > 0
    assert "runs" in result
    assert isinstance(result["runs"], list)

    runs = db.query(EvaluationRun).all()
    assert len(runs) >= 2  # at least one per-rule run + overall
