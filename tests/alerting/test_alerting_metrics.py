"""Alert metrics tests (spec 3.36, 3.37)."""

from __future__ import annotations

from datetime import timedelta

from backend.alerting.engine import process_detection
from backend.alerting.metrics import metrics
from tests.alerting.helpers import T0, detection, stored_alerts


def test_total_and_severity_counts(db):
    process_detection(db, detection(), now=T0)
    process_detection(
        db,
        detection(detector_id="D002", mitre="T1110", host="h2", severity="medium"),
        now=T0,
    )
    result = metrics(db, now=T0)
    assert result["total_alerts"] == 2
    assert result["high_alerts"] == 1
    assert result["medium_alerts"] == 1
    assert result["critical_alerts"] == 0
    assert result["low_alerts"] == 0


def test_open_and_deduplicated_counts(db):
    process_detection(db, detection(), now=T0)
    process_detection(db, detection(minutes_ago=0.1), now=T0)
    alert = stored_alerts(db)[0]
    alert.status = "ACKNOWLEDGED"
    db.commit()
    result = metrics(db, now=T0)
    assert result["open_alerts"] == 0
    assert result["deduplicated_alerts"] == 1
    assert result["occurrence_count"] == 2


def test_noise_metrics(db):
    """3 detections -> 2 alerts -> reduction 1/3, dup ratio 1/2."""
    process_detection(db, detection(), now=T0)
    process_detection(db, detection(minutes_ago=0.1), now=T0)
    process_detection(db, detection(host="other"), now=T0)
    result = metrics(db, now=T0)
    assert result["total_alerts"] == 2
    assert result["alerts_per_detection"] == round(2 / 3, 4)
    assert result["alert_reduction_ratio"] == round(1 / 3, 4)
    assert result["duplicate_alert_ratio"] == 0.5
    assert result["occurrences_per_alert"] == 1.5


def test_mtta_and_mttr_with_sample_sizes(db):
    a = process_detection(db, detection(), now=T0)
    a.status = "ACKNOWLEDGED"
    a.acknowledged_at = T0 + timedelta(minutes=4)
    a.status = "RESOLVED"
    a.resolved_at = T0 + timedelta(minutes=10)
    db.commit()
    result = metrics(db, now=T0 + timedelta(hours=1))
    assert result["mean_time_to_acknowledge_minutes"] == 4.0
    assert result["median_time_to_acknowledge_minutes"] == 4.0
    assert result["mtta_sample_size"] == 1
    assert result["mean_time_to_resolve_minutes"] == 10.0
    assert result["mttr_sample_size"] == 1


def test_mtta_none_without_acknowledgement(db):
    process_detection(db, detection(), now=T0)
    result = metrics(db, now=T0)
    assert result["mean_time_to_acknowledge_minutes"] is None
    assert result["mtta_sample_size"] == 0


def test_age_buckets(db):
    process_detection(db, detection(minutes_ago=2), now=T0)
    process_detection(db, detection(host="h2", minutes_ago=40), now=T0)
    process_detection(db, detection(host="h3", minutes_ago=200), now=T0)
    process_detection(db, detection(host="h4", minutes_ago=600), now=T0)
    result = metrics(db, now=T0)["age_buckets"]
    assert result["0-15m"] == 1
    assert result["15-60m"] == 1
    assert result["1-4h"] == 1
    assert result["4h+"] == 1


def test_feedback_counts_in_metrics(db):
    process_detection(db, detection(), now=T0)
    from backend.alerting.feedback import submit

    submit(db, stored_alerts(db)[0].alert_id, "FALSE_POSITIVE", analyst="a")
    db.commit()
    result = metrics(db, now=T0)
    assert result["false_positive_count"] == 1
    assert result["feedback_count"] == 1


def test_empty_store_metrics(db):
    result = metrics(db, now=T0)
    assert result["total_alerts"] == 0
    assert result["alert_reduction_ratio"] is None
    assert result["alerts_per_detection"] is None
    assert result["occurrences_per_alert"] == 0.0
