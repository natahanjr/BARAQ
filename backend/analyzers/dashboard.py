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


def compute_security_score(session: Session) -> float:
    """Security score 0-100 derived from open alerts."""
    score = 100.0
    counts = dict(
        session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.status == "open")
            .group_by(Alert.severity)
        ).all()
    )
    for severity, penalty in SECURITY_SCORE_PENALTY.items():
        score -= counts.get(severity, 0) * penalty
    return round(max(0.0, min(100.0, score)), 1)


def dashboard_summary(session: Session) -> dict:
    """Aggregated KPIs for the main dashboard."""
    total_events = session.scalar(select(func.count(NormalizedEvent.id))) or 0
    active_alerts = session.scalar(
        select(func.count(Alert.id)).where(Alert.status == "open")
    ) or 0
    critical_threats = session.scalar(
        select(func.count(Alert.id)).where(
            Alert.status == "open", Alert.severity.in_(["critical", "high"])
        )
    ) or 0
    anomalies = session.scalar(
        select(func.count(NormalizedEvent.id)).where(NormalizedEvent.is_anomaly.is_(True))
    ) or 0

    hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    events_last_hour = session.scalar(
        select(func.count(NormalizedEvent.id)).where(NormalizedEvent.timestamp >= hour_ago)
    ) or 0

    severity_counts = {
        s: session.scalar(
            select(func.count(Alert.id)).where(
                Alert.status == "open", Alert.severity == s
            )
        )
        or 0
        for s in SEVERITY_ORDER
    }

    score = compute_security_score(session)
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


def event_timeline(session: Session, hours: int = 24) -> list[dict]:
    """Event counts bucketed per hour for the timeline chart."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = session.execute(
        select(
            func.strftime("%Y-%m-%dT%H:00:00", func.datetime(NormalizedEvent.timestamp, "localtime")).label("bucket"),
            func.count(NormalizedEvent.id),
        )
        .where(NormalizedEvent.timestamp >= since)
        .group_by("bucket")
        .order_by("bucket")
    ).all()
    return [{"bucket": r[0], "count": int(r[1])} for r in rows]


def alert_timeline(session: Session, hours: int = 24) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = session.execute(
        select(
            func.strftime("%Y-%m-%dT%H:00:00", func.datetime(Alert.created_at, "localtime")).label("bucket"),
            func.count(Alert.id),
        )
        .where(Alert.created_at >= since)
        .group_by("bucket")
        .order_by("bucket")
    ).all()
    return [{"bucket": r[0], "count": int(r[1])} for r in rows]


def threat_categories(session: Session) -> list[dict]:
    rows = session.execute(
        select(Alert.mitre_tactic, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.mitre_tactic)
    ).all()
    return [{"tactic": r[0] or "Unknown", "count": int(r[1])} for r in rows]


def severity_distribution(session: Session) -> list[dict]:
    return [
        {"severity": s, "count": session.scalar(
            select(func.count(Alert.id)).where(Alert.status == "open", Alert.severity == s)
        ) or 0}
        for s in SEVERITY_ORDER
    ]


def attack_stats(session: Session) -> list[dict]:
    rows = session.execute(
        select(Alert.name, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.name)
        .order_by(func.count(Alert.id).desc())
    ).all()
    return [{"attack": r[0], "count": int(r[1])} for r in rows]


def top_attackers(session: Session, limit: int = 5) -> list[dict]:
    """Most frequent users/IPs in open alert evidence (top talkers)."""
    alerts = session.scalars(select(Alert).where(Alert.status == "open")).all()
    from collections import Counter

    users: Counter = Counter()
    for a in alerts:
        if a.mitre_id == "T1110" and a.evidence:
            import re
            m = re.search(r"account '([^']+)'", a.evidence)
            if m:
                users[m.group(1)] += 1
    return [{"user": u, "count": c} for u, c in users.most_common(limit)]


def user_behavior(session: Session, limit: int = 8) -> list[dict]:
    """Per-user login behavior statistics (success/failure/avg risk)."""
    from sqlalchemy import case, func as sa_func

    rows = session.execute(
        select(
            NormalizedEvent.user,
            sa_func.sum(case((NormalizedEvent.event_id == 4624, 1), else_=0)).label("successes"),
            sa_func.sum(case((NormalizedEvent.event_id == 4625, 1), else_=0)).label("failures"),
            sa_func.avg(NormalizedEvent.risk_score).label("avg_risk"),
            sa_func.count(NormalizedEvent.id).label("total"),
        )
        .where(NormalizedEvent.event_id.in_([4624, 4625]))
        .group_by(NormalizedEvent.user)
        .order_by(sa_func.count(NormalizedEvent.id).desc())
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


def detection_method_breakdown(session: Session) -> list[dict]:
    """Open alerts grouped by detection method (rule / hybrid)."""
    rows = session.execute(
        select(Alert.detection_method, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.detection_method)
    ).all()
    return [{"method": r[0] or "rule", "count": int(r[1])} for r in rows]


def risk_distribution(session: Session) -> list[dict]:
    """Open alerts grouped by hybrid risk level."""
    rows = session.execute(
        select(Alert.risk_level, func.count(Alert.id))
        .where(Alert.status == "open")
        .group_by(Alert.risk_level)
    ).all()
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
