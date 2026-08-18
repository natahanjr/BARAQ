"""Phase 4 metrics tests (spec 4.39, 4.40, 4.41)."""
from backend.aggregation.engine import process_alerts
from backend.aggregation.evaluation import run_evaluation
from backend.aggregation.metrics import metrics

from tests.aggregation.helpers import GROUP_T0, fabricate_alerts, stored_groups


def test_metrics_all_fields(db):
    alerts = fabricate_alerts(
        db,
        [
            dict(minutes_ago=5.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=4.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=3.0),
            dict(detector_id="D003", host="finance-host", user="bob",
                 source_ip="203.0.113.7", mitre="T1059.001", minutes_ago=2.0),
            dict(detector_id="D005", host="backup-host", user="system",
                 source_ip="203.0.113.9", mitre="T1486", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    result = metrics(db, now=GROUP_T0)

    assert result["total_groups"] == 3
    assert result["active_groups"] == 3
    assert result["quiet_groups"] == 0
    assert result["closed_groups"] == 0
    assert result["single_alert_groups"] == 2
    assert result["multi_alert_groups"] == 1
    assert result["max_alerts_per_group"] == 3
    assert result["mean_alerts_per_group"] == round(5 / 3, 2)
    assert result["median_alerts_per_group"] == 1.0
    assert result["group_reduction_ratio"] == round(1 - 3 / 5, 4)
    assert result["group_assignment_rate"] == 1.0
    assert result["unassigned_alerts"] == 0
    assert result["sample_size_alerts"] == 5
    assert result["sample_size_groups"] == 3


def test_metrics_expose_sample_size(db):
    result = metrics(db, now=GROUP_T0)
    assert result["sample_size_alerts"] == 0
    assert result["sample_size_groups"] == 0
    assert result["group_reduction_ratio"] == 0.0


def test_evaluation_reports_raw_counts_not_fake_accuracy(db):
    counts = run_evaluation(db)
    for key in (
        "labeled_groups", "correct_groupings", "incorrect_groupings",
        "over_grouping", "under_grouping",
    ):
        assert key in counts
    assert counts["labeled_groups"] >= 8
    assert counts["correct_groupings"] + counts["incorrect_groupings"] == counts["labeled_groups"]
    assert "accuracy" not in counts


def test_evaluation_corpus_is_fully_correct(db):
    counts = run_evaluation(db)
    assert counts["over_grouping"] == 0
    assert counts["under_grouping"] == 0
    assert counts["correct_groupings"] == counts["labeled_groups"]