"""False-positive analysis over existing alerts (roadmap P0).

Aggregates per-rule signal from the alert history and scores each rule with
an *FP candidate score* - the heuristic probability that its alerts are
development/test noise rather than real detections:

    FP score  = 0.30 * closed_ratio        (analysts closed without acting)
              + 0.25 * quiet_ratio          (no response actions ever taken)
              + 0.20 * trigger_density      (repeats suggest noise, not novel
                                             behaviour)
              + 0.15 * confidence_penalty   (low rule confidence)
              + 0.10 * severity_penalty     (stayed low - nothing escalated)

The score is a ranking aid for tuning, not a verdict: the analyst decides.
Every component is derived from data BARAQ already stores, so the analysis
costs one read-only query per rule.
"""
from __future__ import annotations

import logging
import re
from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.models import Alert, AlertAction, AnalystNote

logger = logging.getLogger("baraq.fp_analysis")

_ACTIONED = ("block_ip", "kill_process", "quarantine", "isolate",
             "disable_account", "escalate", "fix")
_WORD_RE = re.compile(r"[A-Za-z0-9_.\\/-]{4,}")


def analyze(session: Session, org: str = "", limit_rules: int = 50) -> dict:
    """Run the FP analysis and return the per-rule breakdown."""
    stmt = select(Alert)
    if org:
        stmt = stmt.where(Alert.org == org)
    alerts = list(session.scalars(stmt).all())
    if not alerts:
        return {"items": [], "total_alerts": 0, "rules_analyzed": 0,
                "top_fp_candidates": []}

    by_rule: dict[str, list[Alert]] = {}
    for alert in alerts:
        by_rule.setdefault(alert.rule, []).append(alert)

    action_count = dict(
        session.execute(
            select(AlertAction.alert_id, func.count(AlertAction.id))
            .where(AlertAction.alert_id.in_([a.id for a in alerts]))
            .group_by(AlertAction.alert_id)
        ).all()
    )
    note_count = dict(
        session.execute(
            select(AnalystNote.alert_id, func.count(AnalystNote.id))
            .where(AnalystNote.alert_id.in_([a.id for a in alerts]))
            .group_by(AnalystNote.alert_id)
        ).all()
    )

    items: list[dict] = []
    for rule, rows in by_rule.items():
        total = len(rows)
        closed = sum(1 for a in rows if a.status in ("closed", "resolved"))
        active = total - closed
        triggered = sum(a.trigger_count or 1 for a in rows)
        confidence = sum(a.confidence or 0.5 for a in rows) / total
        risks = Counter((a.risk_level or "LOW").upper() for a in rows)
        severities = Counter(a.severity for a in rows)

        actioned = sum(1 for a in rows if action_count.get(a.id, 0) > 0)
        noted = sum(1 for a in rows if note_count.get(a.id, 0) > 0)
        # A rule is "quiet" when its alerts were closed without any response
        # action AND without analyst notes - nobody ever acted on them.
        quiet = sum(
            1 for a in rows
            if a.status in ("closed", "resolved")
            and action_count.get(a.id, 0) == 0
            and note_count.get(a.id, 0) == 0
        )

        closed_ratio = closed / total
        quiet_ratio = quiet / total
        trigger_density = min(1.0, (triggered / total) / 12.0)  # 12+ repeats = saturated
        confidence_penalty = 1.0 - min(1.0, confidence)
        severity_penalty = 1.0 - min(
            1.0, sum(severities.get(s, 0) * w for s, w in
                     (("critical", 1.0), ("high", 0.7), ("medium", 0.4), ("low", 0.1))) / total
        )

        fp_score = round(
            0.30 * closed_ratio
            + 0.25 * quiet_ratio
            + 0.20 * trigger_density
            + 0.15 * confidence_penalty
            + 0.10 * severity_penalty,
            3,
        )

        tokens: Counter = Counter()
        for alert in rows[:60]:
            for word in _WORD_RE.findall(alert.evidence or ""):
                if len(word) >= 4:
                    tokens[word.lower()] += 1
        top_tokens = [w for w, _ in tokens.most_common(8)]

        demo_share = sum(1 for a in rows if a.demo) / total

        items.append({
            "rule": rule,
            "total": total,
            "active": active,
            "closed": closed,
            "avg_trigger_count": round(triggered / total, 2),
            "avg_confidence": round(confidence, 3),
            "risk_distribution": dict(risks),
            "severity_distribution": dict(severities),
            "closed_without_action": quiet,
            "actioned_count": actioned,
            "noted_count": noted,
            "demo_share": round(demo_share, 3),
            "fp_candidate_score": fp_score,
            "top_evidence_tokens": top_tokens,
        })

    items.sort(key=lambda i: -i["fp_candidate_score"])
    return {
        "items": items[:limit_rules],
        "total_alerts": len(alerts),
        "rules_analyzed": len(by_rule),
        "top_fp_candidates": items[:5],
    }

# ---------------------------------------------------------------------------
# FP clustering (roadmap: one triage decision per behaviour, not N rows).
# ---------------------------------------------------------------------------

_PARENT_RE = None  # compiled lazily to avoid import cycles


def clusters(session: Session, org: str = "", open_only: bool = True) -> dict:
    """Group open alerts by behaviour signature (rule + subject + parent).

    Analysts see "one decision" per cluster instead of dozens of rows; the
    cluster carries the alert ids so bulk actions apply in one click.
    """
    from backend.context.engine import assess_for_alert

    stmt = select(Alert)
    if org:
        stmt = stmt.where(Alert.org == org)
    if open_only:
        stmt = stmt.where(Alert.status == "open")
    rows = list(session.scalars(stmt.order_by(Alert.created_at.desc())).all())

    groups: dict[tuple, dict] = {}
    for alert in rows:
        facts = assess_for_alert(session, alert)
        subject = next(
            (
                p.lower()
                for p in facts.processes
                if facts.reputation.get(p.lower()) in ("trusted", "system", "developer")
            ),
            (facts.processes[0].lower() if facts.processes else "-"),
        )
        parent = facts.parent_names[0].lower() if facts.parent_names else "-"
        key = ((alert.rule or "?"), subject, parent)
        g = groups.setdefault(
            key,
            {
                "rule": key[0],
                "subject": key[1],
                "parent": key[2],
                "count": 0,
                "severities": {},
                "alert_ids": [],
                "latest": None,
            },
        )
        g["count"] += 1
        g["severities"][alert.severity] = g["severities"].get(alert.severity, 0) + 1
        if len(g["alert_ids"]) < 200:
            g["alert_ids"].append(alert.id)
        created = alert.created_at.isoformat() if alert.created_at else ""
        if not g["latest"] or created > g["latest"]:
            g["latest"] = created

    out = sorted(groups.values(), key=lambda g: -g["count"])
    return {
        "clusters": out,
        "cluster_count": len(out),
        "alerts_covered": sum(g["count"] for g in out),
    }
