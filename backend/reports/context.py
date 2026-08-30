"""Report data assembly - shared context for all report formats.

Both report types derive their content from the live database:

* Executive Security Report - security score, threat summary, risk level.
* Technical Report - evidence, event timeline, MITRE ATT&CK mapping,
  recommendations.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.analyzers.dashboard import (
    alert_timeline,
    attack_stats,
    dashboard_summary,
    event_timeline,
    severity_distribution,
    threat_categories,
)
from backend.database.models import Alert, NormalizedEvent
from backend.mitre.attack import categories as mitre_categories
from backend.risk.scoring import risk_level

#: Exec-report descriptions keyed by the canonical risk level (see risk/scoring.py).
RISK_DESCRIPTIONS = {
    "LOW": "Environment operating normally with minor findings.",
    "MEDIUM": "Active threats present; investigate promptly.",
    "HIGH": "Elevated threat activity; immediate response required.",
    "CRITICAL": "Critical compromise indicators; engage incident response.",
}


def _risk_level(security_score: float) -> tuple[str, str]:
    """Map the security score to a risk level using the single canonical mapping.

    The security score runs 100 (healthy) → 0 (compromised), so it is inverted
    to a 0-100 risk scale before applying ``risk_level`` (the same function and
    thresholds used for alerts: >=85 CRITICAL, >=65 HIGH, >=40 MEDIUM, else LOW).
    """
    risk = max(0.0, min(100.0, 100.0 - security_score))
    level = risk_level(risk)
    return level, RISK_DESCRIPTIONS.get(level, RISK_DESCRIPTIONS["LOW"])


def executive_context(session: Session) -> dict:
    summary = dashboard_summary(session)
    score = summary["security_score"]
    label, desc = _risk_level(score)

    alerts = session.scalars(select(Alert).where(Alert.status == "open")).all()
    top_threats = [
        {
            "name": a.name,
            "severity": a.severity,
            "mitre_id": a.mitre_id,
            "mitre_tactic": a.mitre_tactic,
            "status": a.status,
        }
        for a in alerts[:10]
    ]

    return {
        "title": "Executive Security Report",
        "generated_at": datetime.now(UTC).isoformat(),
        "period": "Last 24 hours",
        "security_score": score,
        "risk_level": label,
        "risk_description": desc,
        "summary": summary,
        "top_threats": top_threats,
        "threat_categories": threat_categories(session),
        "severity_distribution": severity_distribution(session),
        "attack_stats": attack_stats(session),
    }


def technical_context(session: Session) -> dict:
    alerts = session.scalars(
        select(Alert).where(Alert.status == "open").order_by(Alert.created_at.desc())
    ).all()

    alert_details = []
    for a in alerts:
        detail = a.to_dict()
        events = [link.event.to_dict() for link in a.events[:20]]
        detail["events"] = events
        alert_details.append(detail)

    recent_events = session.scalars(
        select(NormalizedEvent).order_by(NormalizedEvent.timestamp.desc()).limit(100)
    ).all()

    return {
        "title": "Technical Security Report",
        "generated_at": datetime.now(UTC).isoformat(),
        "alerts": alert_details,
        "event_timeline": event_timeline(session),
        "alert_timeline": alert_timeline(session),
        "recent_events": [e.to_dict() for e in recent_events],
        "mitre_coverage": [
            {"tactic": tactic, "techniques": [t["id"] + " " + t["name"] for t in techs]}
            for tactic, techs in mitre_categories().items()
        ],
        "summary": dashboard_summary(session),
    }
