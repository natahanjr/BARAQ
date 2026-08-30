"""Alert feedback tests (spec 3.14, 3.15, 3.34)."""

from __future__ import annotations

import pytest

from backend.alerting.feedback import for_alert, stats, submit
from tests.alerting.helpers import stored_feedback


def test_feedback_types_accepted(db):
    for kind in (
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "BENIGN",
        "DUPLICATE",
        "EXPECTED_ACTIVITY",
        "UNKNOWN",
    ):
        submit(
            db, "ALR-000001", kind, analyst="analyst@example", comment=f"note {kind}"
        )
    db.commit()
    rows = stored_feedback(db)
    assert len(rows) == 6
    first = rows[0]
    assert first.alert_id == "ALR-000001"
    assert first.analyst_id == "analyst@example"
    assert first.comment == "note TRUE_POSITIVE"


def test_invalid_feedback_type_rejected(db):
    with pytest.raises(ValueError, match="invalid feedback type"):
        submit(db, "ALR-000001", "MAYBE")


def test_comment_optional(db):
    submit(db, "ALR-000001", "BENIGN", analyst="analyst@example")
    db.commit()
    assert stored_feedback(db)[0].comment == ""


def test_for_alert_ordered(db):
    submit(db, "ALR-000001", "TRUE_POSITIVE", analyst="a@x")
    submit(db, "ALR-000002", "FALSE_POSITIVE", analyst="b@x")
    db.commit()
    rows = for_alert(db, "ALR-000001")
    assert [r.alert_id for r in rows] == ["ALR-000001"]
    assert len(for_alert(db, "ALR-000002")) == 1


def test_stats_counts_all_types(db):
    submit(db, "A", "TRUE_POSITIVE", analyst="a")
    submit(db, "B", "FALSE_POSITIVE", analyst="a")
    submit(db, "C", "BENIGN", analyst="a")
    submit(db, "D", "DUPLICATE", analyst="a")
    db.commit()
    result = stats(db, min_labeled_for_fpr=10)
    assert result["total_feedback"] == 4
    assert result["true_positives"] == 1
    assert result["false_positives"] == 1
    assert result["benign"] == 1
    assert result["duplicates"] == 1
    assert result["unknown"] == 0


def test_fpr_never_from_tiny_sample(db):
    submit(db, "A", "FALSE_POSITIVE", analyst="a")
    db.commit()
    result = stats(db, min_labeled_for_fpr=10)
    assert result["false_positive_rate"] is None
    assert result["labeled_alerts"] == 1
    assert result["min_labeled_required"] == 10


def test_fpr_only_after_enough_labeled_data(db):
    for i in range(10):
        submit(db, f"A{i}", "FALSE_POSITIVE" if i % 2 else "TRUE_POSITIVE", analyst="a")
    db.commit()
    result = stats(db, min_labeled_for_fpr=10)
    assert result["false_positive_rate"] == 0.5
    assert result["labeled_alerts"] == 10
