"""Detection quality gates (precision / recall) as hard test assertions.

Wraps the Phase-2 8-scenario benchmark and the 5-scenario evaluation so a
regression that drops detection quality fails CI instead of shipping.
Thresholds are the *measured* floors from a healthy run, not aspirational
targets - tighten only when the system actually improves.
"""

from __future__ import annotations

import pytest

from backend.evaluation.evaluator import _metrics, run_evaluation
from tests.detection.test_detection_evaluation import evaluate_scenarios


# ---------------------------------------------------------------------------
# Scenario-level gates (Phase 2: 5 TP + 3 TN)
# ---------------------------------------------------------------------------
MIN_SCENARIO_PRECISION = 1.0
MIN_SCENARIO_RECALL = 1.0
MIN_SCENARIO_F1 = 1.0
MAX_SCENARIO_FPR = 0.0


def test_scenario_benchmark_precision_recall_gates(db):
    """Every labeled Phase-2 scenario must keep its outcome (TP/TN/FP/FN)."""
    report = evaluate_scenarios(db)
    m = report["metrics"]
    assert m["FP"] == 0, f"false positives on benchmark: {m}"
    assert m["FN"] == 0, f"false negatives on benchmark: {m}"
    assert m["precision"] >= MIN_SCENARIO_PRECISION, m
    assert m["recall"] >= MIN_SCENARIO_RECALL, m
    assert m["f1"] >= MIN_SCENARIO_F1, m
    assert m["fpr"] <= MAX_SCENARIO_FPR, m
    for r in report["results"]:
        assert r["outcome"] == r["label"], (
            f"{r['id']}: label={r['label']} outcome={r['outcome']} "
            f"fired={r['fired']} expected={r['expected']}"
        )


# ---------------------------------------------------------------------------
# Fixture-suite gates (brute_force / powershell / privilege_escalation /
# persistence / port_scan + benign baseline via run_evaluation)
# ---------------------------------------------------------------------------
MIN_SUITE_PRECISION = 0.80
MIN_SUITE_RECALL = 0.90
MIN_SUITE_F1 = 0.85
MAX_SUITE_FPR = 0.10


def test_fixture_suite_precision_recall_gates(db):
    from tests.conftest import run_simulation

    run_simulation(db)
    result = run_evaluation(db, with_ml=False)
    overall = result["overall"]
    # overall row uses scenario="overall" with accumulated TP/FP/TN/FN
    tp = overall.get("true_positives", 0)
    fp = overall.get("false_positives", 0)
    tn = overall.get("true_negatives", 0)
    fn = overall.get("false_negatives", 0)
    m = _metrics(tp, fp, tn, fn)
    assert m["precision"] >= MIN_SUITE_PRECISION, (
        f"precision {m['precision']:.3f} < {MIN_SUITE_PRECISION} "
        f"(tp={tp} fp={fp} fn={fn})"
    )
    assert m["recall"] >= MIN_SUITE_RECALL, (
        f"recall {m['recall']:.3f} < {MIN_SUITE_RECALL} (tp={tp} fn={fn})"
    )
    assert m["f1_score"] >= MIN_SUITE_F1, m
    assert m["false_positive_rate"] <= MAX_SUITE_FPR, m


def test_metrics_helper_gates():
    """Sanity: the gate math itself is standard precision/recall."""
    perfect = _metrics(tp=10, fp=0, tn=5, fn=0)
    assert perfect["precision"] == 1.0
    assert perfect["recall"] == 1.0
    half = _metrics(tp=5, fp=5, tn=5, fn=5)
    assert half["precision"] == pytest.approx(0.5)
    assert half["recall"] == pytest.approx(0.5)
    assert half["f1_score"] == pytest.approx(0.5)
