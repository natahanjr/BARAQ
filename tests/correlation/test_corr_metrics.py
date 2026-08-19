"""Phase 5 metrics + evaluation tests (spec 5.61, 5.62)."""
from backend.correlation.evaluation import run_evaluation
from backend.correlation.metrics import metrics
from backend.correlation.engine import correlate

from tests.correlation.helpers import (
    CORR_T0,
    canonical_specs,
    make_groups,
    stored_correlations,
)


def test_metrics_compression_and_distribution(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    m = metrics(db, now=CORR_T0)
    assert m["total_findings"] == 1
    assert m["sample_size_groups"] == 5
    assert m["group_reduction_ratio"] == round(1 - 1 / 5, 4)
    assert m["cross_host_findings"] == 1
    assert m["cross_user_findings"] == 0
    assert m["median_confidence"] == 0.88
    assert m["type_distribution"] == {"LATERAL_MOVEMENT": 1}
    assert m["rule_distribution"]["R005"] == 1
    assert "sample_size_findings" in m
    assert m["edges_total"] > 0


def test_metrics_empty_database_is_zero_safe(db):
    m = metrics(db, now=CORR_T0)
    assert m["total_findings"] == 0
    assert m["group_reduction_ratio"] == 0.0
    assert m["median_confidence"] == 0.0
    assert m["sample_size_groups"] == 0


def test_evaluation_reports_raw_counts_only(db):
    counts = run_evaluation(db)
    assert set(counts) == {
        "labeled_chains", "true_positives", "false_positives",
        "true_negatives", "false_negatives", "over_correlation",
        "under_correlation",
    }
    assert counts["true_positives"] >= 1
    assert counts["labeled_chains"] == (
        counts["true_positives"] + counts["false_positives"]
        + counts["true_negatives"] + counts["false_negatives"]
    )


def test_evaluation_never_fabricates_accuracy(db):
    counts = run_evaluation(db)
    for key in ("accuracy", "precision", "recall", "f1"):
        assert key not in counts