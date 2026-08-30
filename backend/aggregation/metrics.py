"""Phase 4 group metrics (spec 4.39, 4.40).

Compression + quality tracking. Group counts, alerts-per-group
distribution, reduction ratio, assignment rate and over/under-grouping
counters (from the labeled evaluation corpus - never a fake accuracy
percentage, spec 4.41). Every rate exposes its sample size.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.aggregation.models import BehaviorGroupMember, BehaviorGroupRecord
from backend.alerting.models import AlertRecord


def metrics(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    groups = list(
        db.scalars(select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id)).all()
    )
    total_alerts = db.scalars(select(func.count()).select_from(AlertRecord)).one()
    grouped_alerts = db.scalars(
        select(func.count()).select_from(BehaviorGroupMember)
    ).one()

    alert_counts = sorted(g.alert_count for g in groups)
    single = sum(1 for c in alert_counts if c == 1)
    multi = sum(1 for c in alert_counts if c > 1)

    def _percentile(pct: float) -> float | None:
        if not alert_counts:
            return None
        import math

        index = math.ceil(pct / 100 * len(alert_counts)) - 1
        return float(alert_counts[max(0, min(index, len(alert_counts) - 1))])

    return {
        "total_groups": len(groups),
        "active_groups": sum(1 for g in groups if g.status == "ACTIVE"),
        "quiet_groups": sum(1 for g in groups if g.status == "QUIET"),
        "closed_groups": sum(1 for g in groups if g.status == "CLOSED"),
        "alerts_per_group": alert_counts,
        "mean_alerts_per_group": (
            round(sum(alert_counts) / len(alert_counts), 2) if alert_counts else 0.0
        ),
        "median_alerts_per_group": _percentile(50) or 0.0,
        "max_alerts_per_group": alert_counts[-1] if alert_counts else 0,
        "single_alert_groups": single,
        "multi_alert_groups": multi,
        #: 1 - groups/alerts: 100 alerts -> 24 groups = 76% reduction (4.39).
        "group_reduction_ratio": (
            round(1 - len(groups) / total_alerts, 4) if total_alerts else 0.0
        ),
        "unassigned_alerts": total_alerts - grouped_alerts,
        "group_assignment_rate": (
            round(grouped_alerts / total_alerts, 4) if total_alerts else 0.0
        ),
        "sample_size_alerts": total_alerts,
        "sample_size_groups": len(groups),
    }


def evaluation_counts(db: Session) -> dict:
    """Over/under-grouping counters from the labeled corpus (spec 4.40/4.41).

    Reported as raw labeled counts - never a fabricated accuracy
    percentage. Over-grouping: two unrelated alert sets merged into one
    group. Under-grouping: two related alert sets separated.
    """
    from backend.aggregation.evaluation import run_evaluation

    return run_evaluation(db)
