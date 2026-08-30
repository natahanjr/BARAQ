"""Phase 6 risk metrics (spec 6.55, 6.74).

Aggregate counts over the entity risk store - never fabricated accuracy.
Latency percentiles come from the per-calculation duration recorded in the
audit trail (6.74).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.risk.calculator import utcnow
from backend.risk.contract import ENTITY_TYPES
from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
    EntityRiskV2Snapshot,
)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if pct >= 100:
        return ordered[-1]
    index = round(pct / 100.0 * (len(ordered) - 1))
    return ordered[index]


def risk_metrics(db: Session, now: datetime | None = None) -> dict:
    now = now or utcnow()
    total = db.scalars(select(func.count()).select_from(EntityRiskV2)).one()
    with_risk = db.scalars(
        select(func.count()).select_from(EntityRiskV2).where(EntityRiskV2.score > 0)
    ).one()

    severity_counts: dict[str, int] = {}
    for severity in ("critical", "high", "medium", "low", "minimal"):
        severity_counts[severity] = db.scalars(
            select(func.count())
            .select_from(EntityRiskV2)
            .where(EntityRiskV2.severity == severity.upper())
        ).one()

    scores = [
        float(row)
        for row in db.scalars(
            select(EntityRiskV2.score).where(EntityRiskV2.score > 0)
        ).all()
    ]
    average = round(sum(scores) / len(scores), 2) if scores else 0.0
    median = round(_percentile(scores, 50), 2) if scores else 0.0
    maximum = round(max(scores), 2) if scores else 0.0

    distribution = {
        "0_19": 0,
        "20_39": 0,
        "40_59": 0,
        "60_79": 0,
        "80_100": 0,
    }
    for score in scores:
        if score < 20:
            distribution["0_19"] += 1
        elif score < 40:
            distribution["20_39"] += 1
        elif score < 60:
            distribution["40_59"] += 1
        elif score < 80:
            distribution["60_79"] += 1
        else:
            distribution["80_100"] += 1

    trend_counts = {"RISING": 0, "STABLE": 0, "FALLING": 0, "UNKNOWN": 0}
    for trend in db.scalars(
        select(EntityRiskV2.trend).where(EntityRiskV2.score > 0)
    ).all():
        trend_counts[trend] = trend_counts.get(trend, 0) + 1

    stale = db.scalars(
        select(func.count())
        .select_from(EntityRiskV2)
        .where(EntityRiskV2.state == "STALE")
    ).one()

    by_entity_type: dict[str, dict] = {}
    for entity_type in ENTITY_TYPES:
        per_severity = {
            sev.lower(): 0 for sev in ("critical", "high", "medium", "low", "minimal")
        }
        for severity, count in db.execute(
            select(EntityRiskV2.severity, func.count())
            .where(EntityRiskV2.entity_type == entity_type)
            .group_by(EntityRiskV2.severity)
        ).all():
            per_severity[severity.lower()] = count
        by_entity_type[entity_type] = {
            "total": sum(per_severity.values()),
            **per_severity,
        }

    factor_distribution: dict[str, int] = {}
    for factor_type, count in db.execute(
        select(EntityRiskV2Factor.factor_type, func.count())
        .group_by(EntityRiskV2Factor.factor_type)
        .order_by(EntityRiskV2Factor.factor_type)
    ).all():
        factor_distribution[factor_type] = count

    transitions: dict[str, int] = {}
    for action in db.scalars(
        select(EntityRiskV2AuditEvent.action).where(
            EntityRiskV2AuditEvent.action.in_(("RISK_STATE_CHANGED",))
        )
    ).all():
        transitions[action] = transitions.get(action, 0) + 1

    risk_calculations = db.scalars(
        select(func.count())
        .select_from(EntityRiskV2AuditEvent)
        .where(EntityRiskV2AuditEvent.action == "RISK_RECALCULATED")
    ).one()

    latencies = [
        float(details.get("duration_ms", 0.0))
        for details in db.scalars(
            select(EntityRiskV2AuditEvent.details).where(
                EntityRiskV2AuditEvent.action == "RISK_RECALCULATED"
            )
        ).all()
        if details and details.get("duration_ms") is not None
    ]
    latency = {
        "p50_ms": round(_percentile(latencies, 50), 3),
        "p95_ms": round(_percentile(latencies, 95), 3),
        "p99_ms": round(_percentile(latencies, 99), 3),
        "max_ms": round(_percentile(latencies, 100), 3),
    }

    snapshots = db.scalars(select(func.count()).select_from(EntityRiskV2Snapshot)).one()
    expired = db.scalars(
        select(func.count())
        .select_from(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.expired_at.is_not(None))
    ).one()

    return {
        "as_of": now.isoformat(),
        "total_entities": total,
        "entities_with_risk": with_risk,
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "minimal": severity_counts["minimal"],
        "average_score": average,
        "median_score": median,
        "max_score": maximum,
        "score_distribution": distribution,
        "rising": trend_counts["RISING"],
        "falling": trend_counts["FALLING"],
        "stable": trend_counts["STABLE"],
        "stale_entities": stale,
        "by_entity_type": by_entity_type,
        "factor_distribution": factor_distribution,
        "risk_state_transitions": transitions,
        "risk_calculations": risk_calculations,
        "calculation_latency": latency,
        "snapshot_count": snapshots,
        "factor_expiration_count": expired,
    }
