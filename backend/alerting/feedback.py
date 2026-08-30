"""Structured analyst feedback (spec 3.14, 3.15, 3.34).

Every feedback action records alert_id, feedback_type, analyst, timestamp
and an optional comment. False-positive rates are only reported once
enough labeled data exists (``ALERT_MIN_LABELED_FOR_FPR``).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerting.contract import FEEDBACK_TYPES
from backend.alerting.models import AlertFeedback


def submit(
    db: Session,
    alert_id: str,
    feedback_type: str,
    analyst: str = "system",
    comment: str = "",
) -> AlertFeedback:
    if feedback_type not in FEEDBACK_TYPES:
        raise ValueError(f"invalid feedback type {feedback_type!r}")
    row = AlertFeedback(
        alert_id=alert_id,
        feedback_type=feedback_type,
        analyst_id=analyst,
        comment=comment,
    )
    db.add(row)
    db.flush()
    return row


def for_alert(db: Session, alert_id: str) -> list[AlertFeedback]:
    return list(
        db.scalars(
            select(AlertFeedback)
            .where(AlertFeedback.alert_id == alert_id)
            .order_by(AlertFeedback.created_at, AlertFeedback.id)
        ).all()
    )


def stats(db: Session, min_labeled_for_fpr: int) -> dict:
    """Feedback + false-positive statistics (spec 3.15).

    FPR is only computed when ``total_labeled >= min_labeled_for_fpr``;
    otherwise it is None and the labeled count is reported alongside.
    """
    rows = db.scalars(select(AlertFeedback)).all()
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.feedback_type] = counts.get(row.feedback_type, 0) + 1
    labeled = counts.get("TRUE_POSITIVE", 0) + counts.get("FALSE_POSITIVE", 0)
    fpr = None
    if labeled >= min_labeled_for_fpr and labeled > 0:
        fpr = round(counts.get("FALSE_POSITIVE", 0) / labeled, 4)
    return {
        "total_feedback": len(rows),
        "true_positives": counts.get("TRUE_POSITIVE", 0),
        "false_positives": counts.get("FALSE_POSITIVE", 0),
        "benign": counts.get("BENIGN", 0),
        "duplicates": counts.get("DUPLICATE", 0),
        "expected_activity": counts.get("EXPECTED_ACTIVITY", 0),
        "unknown": counts.get("UNKNOWN", 0),
        "false_positive_rate": fpr,
        "labeled_alerts": labeled,
        "min_labeled_required": min_labeled_for_fpr,
    }
