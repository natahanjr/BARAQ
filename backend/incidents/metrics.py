"""Phase 7 incident metrics (spec 7.36, 7.37, 7.49)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from backend.incidents.config import INCIDENT_SLA_MINUTES
from backend.incidents.contract import INCIDENT_PRIORITIES, INCIDENT_SEVERITIES, INCIDENT_STATES
from backend.incidents.models import (
    IncidentV2AuditEvent,
    IncidentV2Feedback,
    IncidentV2,
)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if pct >= 100:
        return ordered[-1]
    index = int(round(pct / 100.0 * (len(ordered) - 1)))
    return ordered[index]


def incident_metrics(db, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    total = db.scalars(select(func.count()).select_from(IncidentV2)).one()
    by_status: dict[str, int] = {s: 0 for s in INCIDENT_STATES}
    for status in db.scalars(select(IncidentV2.status)).all():
        by_status[status] = by_status.get(status, 0) + 1

    active = sum(
        by_status.get(s, 0) for s in ("NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_REQUIRED", "CONTAINED")
    )

    by_severity: dict[str, int] = {s: 0 for s in INCIDENT_SEVERITIES}
    for severity in db.scalars(select(IncidentV2.severity)).all():
        by_severity[severity] = by_severity.get(severity, 0) + 1

    by_priority: dict[str, int] = {p: 0 for p in INCIDENT_PRIORITIES}
    for priority in db.scalars(select(IncidentV2.priority)).all():
        by_priority[priority] = by_priority.get(priority, 0) + 1

    by_policy: dict[str, int] = {}
    for policy_id in db.scalars(select(IncidentV2.policy_id)).all():
        key = policy_id or "none"
        by_policy[key] = by_policy.get(key, 0) + 1

    ages: list[float] = []
    overdue = 0
    within_sla = 0
    breached = 0
    for created_at, priority in db.execute(
        select(IncidentV2.created_at, IncidentV2.priority)
        .where(IncidentV2.status.in_(("NEW", "TRIAGED", "INVESTIGATING", "CONTAINMENT_REQUIRED")))
    ).all():
        age_hours = (now - created_at).total_seconds() / 3600.0
        ages.append(age_hours)
        sla_min = INCIDENT_SLA_MINUTES.get(priority, 480)
        if age_hours * 60 > sla_min:
            breached += 1
            overdue += 1
        else:
            within_sla += 1

    calculations = db.scalars(
        select(func.count()).select_from(IncidentV2AuditEvent).where(
            IncidentV2AuditEvent.action == "INCIDENT_CREATED"
        )
    ).one()
    failures = db.scalars(
        select(func.count()).select_from(IncidentV2AuditEvent).where(
            IncidentV2AuditEvent.action == "INCIDENT_CREATION_FAILED"
        )
    ).one()

    latency = {
        "p50_ms": 0.0,
        "p95_ms": 0.0,
        "p99_ms": 0.0,
        "max_ms": 0.0,
    }

    feedback_counts: dict[str, int] = {}
    for fb_type in db.scalars(select(IncidentV2Feedback.feedback_type)).all():
        feedback_counts[fb_type] = feedback_counts.get(fb_type, 0) + 1

    return {
        "as_of": now.isoformat(),
        "total_incidents": total,
        "active_incidents": active,
        "open_incidents": by_status.get("NEW", 0) + by_status.get("TRIAGED", 0),
        "investigating": by_status.get("INVESTIGATING", 0),
        "contained": by_status.get("CONTAINED", 0),
        "resolved": by_status.get("RESOLVED", 0),
        "closed": by_status.get("CLOSED", 0),
        "suppressed": by_status.get("SUPPRESSED", 0),
        "incidents_by_severity": by_severity,
        "incidents_by_priority": by_priority,
        "incidents_by_policy": by_policy,
        "unassigned": by_status.get("NEW", 0),
        "assigned": total - by_status.get("NEW", 0),
        "overdue_incidents": overdue,
        "within_sla": within_sla,
        "sla_breached": breached,
        "mtta_hours": round(_percentile(ages, 50), 2) if ages else 0.0,
        "mttr_hours": 0.0,
        "median_age_hours": round(_percentile(ages, 50), 2) if ages else 0.0,
        "p50_age_hours": round(_percentile(ages, 50), 2) if ages else 0.0,
        "p95_age_hours": round(_percentile(ages, 95), 2) if ages else 0.0,
        "incident_calculations": calculations,
        "incident_creation_failures": failures,
        "creation_latency": latency,
        "feedback": feedback_counts,
        "sample_size": total,
    }


