"""Alert metrics (spec 3.36, 3.37).

Operational + noise metrics over the v2 alert store. No unsupported
precision: MTTA/MTTR are reported in minutes WITH their sample sizes.
FPR is only surfaced when enough labeled data exists (see feedback.py).
"""
from __future__ import annotations

from datetime import datetime, timezone
from statistics import median

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.alerting.feedback import stats as feedback_stats
from backend.alerting.models import AlertOccurrence, AlertRecord
from backend.config import ALERT_MIN_LABELED_FOR_FPR


def metrics(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    alerts = list(db.scalars(select(AlertRecord)).all())
    total = len(alerts)
    occurrences = db.scalar(select(func.count()).select_from(AlertOccurrence)) or 0

    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    age_buckets = {"0-15m": 0, "15-60m": 0, "1-4h": 0, "4h+": 0}
    for a in alerts:
        by_status[a.status] = by_status.get(a.status, 0) + 1
        by_severity[a.severity] = by_severity.get(a.severity, 0) + 1
        age_m = (now - a.first_seen).total_seconds() / 60 if a.first_seen else 0
        if age_m <= 15:
            age_buckets["0-15m"] += 1
        elif age_m <= 60:
            age_buckets["15-60m"] += 1
        elif age_m <= 240:
            age_buckets["1-4h"] += 1
        else:
            age_buckets["4h+"] += 1

    def _span(a: AlertRecord, start: datetime | None, end: datetime | None) -> float | None:
        if start is None or end is None:
            return None
        return (end - start).total_seconds() / 60

    mtta = [v for v in (_span(a, a.created_at, a.acknowledged_at) for a in alerts) if v is not None]
    mttr = [v for v in (_span(a, a.created_at, a.resolved_at) for a in alerts) if v is not None]

    # Noise metrics (spec 3.37): measured from actual stored data.
    detection_total = sum(len(a.detection_ids or [1]) for a in alerts) if alerts else 0
    reduction = round((1 - total / detection_total), 4) if detection_total else None
    deduplicated = sum(1 for a in alerts if a.occurrence_count > 1)

    fb = feedback_stats(db, ALERT_MIN_LABELED_FOR_FPR)
    return {
        "total_alerts": total,
        "open_alerts": by_status.get("OPEN", 0),
        "critical_alerts": by_severity.get("critical", 0),
        "high_alerts": by_severity.get("high", 0),
        "medium_alerts": by_severity.get("medium", 0),
        "low_alerts": by_severity.get("low", 0),
        "deduplicated_alerts": deduplicated,
        "occurrence_count": occurrences,
        "mean_time_to_acknowledge_minutes": round(sum(mtta) / len(mtta), 1) if mtta else None,
        "median_time_to_acknowledge_minutes": round(median(mtta), 1) if mtta else None,
        "mtta_sample_size": len(mtta),
        "mean_time_to_resolve_minutes": round(sum(mttr) / len(mttr), 1) if mttr else None,
        "median_time_to_resolve_minutes": round(median(mttr), 1) if mttr else None,
        "mttr_sample_size": len(mttr),
        "false_positive_count": fb["false_positives"],
        "true_positive_count": fb["true_positives"],
        "feedback_count": fb["total_feedback"],
        "alert_reduction_ratio": reduction,
        "duplicate_alert_ratio": round(deduplicated / total, 4) if total else 0.0,
        "alerts_per_detection": round(total / detection_total, 4) if detection_total else None,
        "occurrences_per_alert": round(occurrences / total, 2) if total else 0.0,
        "age_buckets": age_buckets,
    }