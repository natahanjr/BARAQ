"""Phase 5 correlation metrics (spec 5.61, 5.62).

Compression + distribution + latency. Every rate exposes its sample size;
raw labeled quality counts come from the evaluation corpus (spec 5.62),
never a fabricated accuracy percentage.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.correlation.models import (
    CorrelationAuditEvent,
    CorrelationEdge,
    CorrelationFindingRecord,
    CorrelationMember,
)


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    import math

    ordered = sorted(values)
    index = math.ceil(50 / 100 * len(ordered)) - 1
    return float(ordered[max(0, min(index, len(ordered) - 1))])


def metrics(db: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    findings = list(
        db.scalars(
            select(CorrelationFindingRecord).order_by(CorrelationFindingRecord.id)
        ).all()
    )
    groups_total = db.scalars(select(func.count()).select_from(CorrelationMember)).one()
    edges_total = db.scalars(select(func.count()).select_from(CorrelationEdge)).one()

    rule_distribution: dict[str, int] = {}
    for event in db.scalars(
        select(CorrelationAuditEvent).where(
            CorrelationAuditEvent.action == "CORRELATION_CREATED"
        )
    ).all():
        rule_id = (event.details or {}).get("rule_id", "unknown")
        rule_distribution[rule_id] = rule_distribution.get(rule_id, 0) + 1

    member_counts = sorted(len(f.member_group_ids or []) for f in findings)
    confidences = [f.confidence for f in findings]
    latencies = [
        (now - f.created_at).total_seconds() if f.created_at else 0.0 for f in findings
    ]

    return {
        "total_findings": len(findings),
        "new_findings": sum(1 for f in findings if f.status == "NEW"),
        "active_findings": sum(1 for f in findings if f.status == "ACTIVE"),
        "quiet_findings": sum(1 for f in findings if f.status == "QUIET"),
        "closed_findings": sum(1 for f in findings if f.status == "CLOSED"),
        "groups_per_finding": member_counts,
        "mean_groups_per_finding": (
            round(sum(member_counts) / len(member_counts), 2) if member_counts else 0.0
        ),
        "median_groups_per_finding": _median([float(c) for c in member_counts]),
        "max_groups_per_finding": member_counts[-1] if member_counts else 0,
        "cross_host_findings": sum(
            1 for f in findings if f.hosts and len(f.hosts) >= 2
        ),
        "cross_user_findings": sum(
            1 for f in findings if f.users and len(f.users) >= 2
        ),
        "median_confidence": _median(confidences),
        "median_age_seconds": _median(latencies),
        "rule_distribution": rule_distribution,
        "type_distribution": {
            correlation_type: sum(
                1 for f in findings if f.correlation_type == correlation_type
            )
            for correlation_type in sorted({f.correlation_type for f in findings})
        },
        "group_reduction_ratio": (
            round(1 - len(findings) / groups_total, 4) if groups_total else 0.0
        ),
        "edges_total": edges_total,
        "sample_size_findings": len(findings),
        "sample_size_groups": groups_total,
    }


def evaluation_counts(db: Session) -> dict:
    """Raw labeled correlation-quality counts (spec 5.62) - no fake
    accuracy percentage."""
    from backend.correlation.evaluation import run_evaluation

    return run_evaluation(db)
