"""Verdict-driven auto-suppression - closing the FP feedback loop.

When analysts mark the same behaviour a false positive repeatedly (>=
``FP_AUTO_SUPPRESS_THRESHOLD``), the system stops asking: a scoped
suppression rule (rule + host) is created automatically from the existing
suppression store. Every auto-rule carries its signature and expiry so it
stays auditable and self-healing.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.context.engine import assess_for_alert
from backend.database.models import Alert, AlertVerdict

logger = logging.getLogger("baraq.auto_suppress")

#: Distinct false_positive verdicts on one signature before auto-suppressing.
FP_AUTO_SUPPRESS_THRESHOLD = 3
AUTO_SUPPRESS_EXPIRY_HOURS = 168.0  # 7 days


def fp_signature(db: Session, alert: Alert) -> dict:
    """(rule, subject_process, parent_process, host) for an alert."""
    facts = assess_for_alert(db, alert)
    subject = next(
        (
            p.lower()
            for p in facts.processes
            if facts.reputation.get(p.lower()) in ("trusted", "system", "developer")
        ),
        (facts.processes[0].lower() if facts.processes else ""),
    )
    parent = facts.parent_names[0].lower() if facts.parent_names else ""
    return {
        "rule": (alert.rule or "").strip(),
        "subject": subject,
        "parent": parent,
        "host": (alert.host or "").lower(),
    }


def count_prior_fps(db: Session, alert: Alert, sig: dict) -> int:
    """False-positive verdicts on OTHER alerts sharing this signature.

    Signature match = same rule + host, and the sibling alert's evidence
    contains both the subject and parent tokens (cheap, index-free match on
    data BARAQ already stores).
    """
    if not sig["rule"] or not sig["subject"]:
        return 0
    candidates = db.scalars(
        select(Alert)
        .where(
            Alert.rule == sig["rule"],
            Alert.host == sig["host"],
            Alert.id != alert.id,
        )
        .limit(200)
    ).all()
    ids = [a.id for a in candidates]
    if not ids:
        return 0
    verdicts = db.scalars(
        select(AlertVerdict).where(
            AlertVerdict.alert_id.in_(ids),
            AlertVerdict.verdict == "false_positive",
        )
    ).all()
    by_alert = {v.alert_id for v in verdicts}
    n = 0
    for a in candidates:
        if a.id not in by_alert:
            continue
        ev = (a.evidence or "").lower()
        if sig["subject"] in ev and (not sig["parent"] or sig["parent"] in ev):
            n += 1
    return n


def maybe_auto_suppress(
    db: Session, alert: Alert, actor: str = "", org: str = ""
) -> dict:
    """Record-analyst-FP hook: create a suppression rule at the threshold."""
    from backend.detection.suppression import create as create_suppression

    sig = fp_signature(db, alert)
    prior = count_prior_fps(db, alert, sig)
    total = prior + 1  # this verdict is itself one FP instance

    if total < FP_AUTO_SUPPRESS_THRESHOLD or not sig["rule"]:
        return {
            "suppressed": False,
            "signature": sig,
            "fp_count": total,
            "threshold": FP_AUTO_SUPPRESS_THRESHOLD,
        }

    reason = (
        f"Auto-suppressed after {total}x false_positive verdicts on "
        f"signature rule={sig['rule']} subject={sig['subject'] or '-'} "
        f"parent={sig['parent'] or '-'}"
    )
    item = create_suppression(
        db,
        rule=sig["rule"],
        host=sig["host"] or "*",
        user="*",
        reason=reason,
        created_by=actor or "auto-suppress",
        org=org,
        expires_hours=AUTO_SUPPRESS_EXPIRY_HOURS,
    )
    logger.info("Auto-suppression created (#%s): %s", item.id, reason)
    return {
        "suppressed": True,
        "suppression_id": item.id,
        "signature": sig,
        "fp_count": total,
        "threshold": FP_AUTO_SUPPRESS_THRESHOLD,
    }
