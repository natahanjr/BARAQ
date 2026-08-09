"""Dashboard analytics - KPI computation for the SOC dashboard and reports."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.config import SECURITY_SCORE_PENALTY
from backend.database.models import (
    Alert,
    DashboardSnapshot,
    NormalizedEvent,
)

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _event_org(org: str | None):
    """Return the ORM equality expression for scoping events, or None."""
    if org is None:
        return None
    return NormalizedEvent.org == org


def _alert_org(org: str | None):
    if org is None:
        return None
    return Alert.org == org


def compute_security_score(session: Session, org: str | None = None) -> float:
    """Security score 0-100 derived from open alerts (optionally per tenant)."""
    score = 100.0
    stmt = select(Alert.severity, func.count(Alert.id)).where(Alert.status == "open")
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    counts = dict(session.execute(stmt.group_by(Alert.severity)).all())
    for severity, penalty in SECURITY_SCORE_PENALTY.items():
        score -= counts.get(severity, 0) * penalty
    return round(max(0.0, min(100.0, score)), 1)


def dashboard_summary(session: Session, org: str | None = None) -> dict:
    """Aggregated KPIs for the main dashboard.

    ``org`` is the tenant scope requested by the caller: ``None`` means the
    whole platform, any string (including "") restricts every counter to
    records tagged with that organization.
    """
    total_events = session.scalar(
        select(func.count(NormalizedEvent.id)).where(*([_event_org(org)] if org is not None else []))
    ) or 0
    active_alerts = session.scalar(
        select(func.count(Alert.id)).where(Alert.status == "open", *([_alert_org(org)] if org is not None else []))
    ) or 0
    critical_threats = session.scalar(
        select(func.count(Alert.id)).where(
            Alert.status == "open",
            Alert.severity.in_(["critical", "high"]),
            *([_alert_org(org)] if org is not None else []),
        )
    ) or 0
    anomalies = session.scalar(
        select(func.count(NormalizedEvent.id)).where(
            NormalizedEvent.is_anomaly.is_(True),
            *([_event_org(org)] if org is not None else []),
        )
    ) or 0

    hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    events_last_hour = session.scalar(
        select(func.count(NormalizedEvent.id)).where(
            NormalizedEvent.timestamp >= hour_ago,
            *([_event_org(org)] if org is not None else []),
        )
    ) or 0

    severity_counts = {
        s: session.scalar(
            select(func.count(Alert.id)).where(
                Alert.status == "open",
                Alert.severity == s,
                *([_alert_org(org)] if org is not None else []),
            )
        )
        or 0
        for s in SEVERITY_ORDER
    }

    score = compute_security_score(session, org=org)
    system_status = (
        "CRITICAL"
        if score < 40
        else ("ATTENTION" if score < 70 else "HEALTHY")
    )

    return {
        "security_score": score,
        "total_events": total_events,
        "active_alerts": active_alerts,
        "critical_threats": critical_threats,
        "anomalies_detected": anomalies,
        "events_last_hour": events_last_hour,
        "system_status": system_status,
        "severity_counts": severity_counts,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _hour_bucket(column, session: Session):
    """Portable SQL expression truncating a UTC datetime column to the hour."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        return func.date_trunc("hour", column)
    if dialect in ("mysql", "mariadb"):
        return func.date_format(column, "%Y-%m-%dT%H:00:00")
    # Timestamps are stored as-naive UTC; avoid ``localtime`` which would
    # shift already-UTC values by the server's local offset.
    return func.strftime("%Y-%m-%dT%H:00:00", column)


def _format_bucket(value) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:00:00")
    text = str(value)
    return text.replace("Z", "T")[:13] + ":00:00" if text.endswith("Z") else text[:19]


def event_timeline(session: Session, hours: int = 24, org: str | None = None) -> list[dict]:
    """Event counts bucketed per hour for the timeline chart."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    bucket = _hour_bucket(NormalizedEvent.timestamp, session)
    stmt = select(bucket.label("bucket"), func.count(NormalizedEvent.id)).where(
        NormalizedEvent.timestamp >= since
    )
    if org is not None:
        stmt = stmt.where(NormalizedEvent.org == org)
    rows = session.execute(stmt.group_by("bucket").order_by("bucket")).all()
    return [{"bucket": _format_bucket(r[0]), "count": int(r[1])} for r in rows]


def alert_timeline(session: Session, hours: int = 24, org: str | None = None) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    bucket = _hour_bucket(Alert.created_at, session)
    stmt = select(bucket.label("bucket"), func.count(Alert.id)).where(
        Alert.created_at >= since
    )
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt.group_by("bucket").order_by("bucket")).all()
    return [{"bucket": _format_bucket(r[0]), "count": int(r[1])} for r in rows]


def threat_categories(session: Session, org: str | None = None) -> list[dict]:
    stmt = select(Alert.mitre_tactic, func.count(Alert.id)).where(Alert.status == "open")
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt.group_by(Alert.mitre_tactic)).all()
    return [{"tactic": r[0] or "Unknown", "count": int(r[1])} for r in rows]


def severity_distribution(session: Session, org: str | None = None) -> list[dict]:
    stmt = select(Alert.severity, func.count(Alert.id)).where(Alert.status == "open")
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt.group_by(Alert.severity)).all()
    counts = dict(rows)
    return [
        {"severity": s, "count": int(counts.get(s, 0))} for s in SEVERITY_ORDER
    ]


def attack_stats(session: Session, org: str | None = None) -> list[dict]:
    stmt = (
        select(Alert.name, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.name)
        .order_by(func.count(Alert.id).desc())
    )
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt).all()
    return [{"attack": r[0], "count": int(r[1])} for r in rows]


def top_attackers(session: Session, limit: int = 5, org: str | None = None) -> list[dict]:
    """Most frequent users/IPs in open alert evidence (top talkers)."""
    import re
    from collections import Counter

    stmt = (
        select(Alert)
        .where(Alert.status == "open", Alert.mitre_id == "T1110", Alert.evidence != "")
    )
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    alerts = session.scalars(stmt).all()
    users: Counter = Counter()
    for a in alerts:
        m = re.search(r"account '([^']+)'", a.evidence or "")
        if m:
            users[m.group(1)] += 1
    return [{"user": u, "count": c} for u, c in users.most_common(limit)]


def user_behavior(
    session: Session, limit: int = 8, since_hours: int = 24, org: str | None = None
) -> list[dict]:
    """Per-user login behavior statistics for the last ``since_hours``."""
    from sqlalchemy import case

    since = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    stmt = select(
        NormalizedEvent.user,
        func.sum(case((NormalizedEvent.event_id == 4624, 1), else_=0)).label("successes"),
        func.sum(case((NormalizedEvent.event_id == 4625, 1), else_=0)).label("failures"),
        func.avg(NormalizedEvent.risk_score).label("avg_risk"),
        func.count(NormalizedEvent.id).label("total"),
    ).where(
        NormalizedEvent.event_id.in_([4624, 4625]),
        NormalizedEvent.timestamp >= since,
    )
    if org is not None:
        stmt = stmt.where(NormalizedEvent.org == org)
    rows = session.execute(
        stmt.group_by(NormalizedEvent.user)
        .order_by(func.count(NormalizedEvent.id).desc())
        .limit(limit)
    ).all()
    return [
        {
            "user": r.user,
            "successes": int(r.successes or 0),
            "failures": int(r.failures or 0),
            "avg_risk": round(float(r.avg_risk or 0.0), 1),
            "total": int(r.total or 0),
        }
        for r in rows
    ]


def detection_method_breakdown(session: Session, org: str | None = None) -> list[dict]:
    """Open alerts grouped by detection method (rule / hybrid)."""
    stmt = (
        select(Alert.detection_method, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.detection_method)
    )
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt).all()
    return [{"method": r[0] or "rule", "count": int(r[1])} for r in rows]


def risk_distribution(session: Session, org: str | None = None) -> list[dict]:
    """Open alerts grouped by hybrid risk level."""
    stmt = (
        select(Alert.risk_level, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.risk_level)
    )
    if org is not None:
        stmt = stmt.where(Alert.org == org)
    rows = session.execute(stmt).all()
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items = [{"risk_level": r[0] or "LOW", "count": int(r[1])} for r in rows]
    items.sort(key=lambda x: order.get(x["risk_level"], 9))
    return items


def snapshot(session: Session) -> DashboardSnapshot:
    """Record a KPI roll-up for historical trending."""
    summary = dashboard_summary(session)
    snap = DashboardSnapshot(
        timestamp=datetime.now(timezone.utc),
        security_score=summary["security_score"],
        total_events=summary["total_events"],
        active_alerts=summary["active_alerts"],
        critical_threats=summary["critical_threats"],
        events_last_hour=summary["events_last_hour"],
    )
    session.add(snap)
    session.commit()
    return snap


#: Record types with scoping support (used by the API layer).
SCOPED_FUNCTIONS = (
    dashboard_summary,
    event_timeline,
    alert_timeline,
    threat_categories,
    severity_distribution,
    attack_stats,
    top_attackers,
    user_behavior,
    detection_method_breakdown,
    risk_distribution,
)