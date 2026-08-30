"""Automatic verdict generation for the investigation view.

Produces a *suggested* analyst verdict (true_positive / false_positive /
expected_behavior / needs_review) with a confidence score and human
readable reasons. Combines the context engine (developer-workflow
dampening), rule reputation, severity/confidence, entity risk, ML
agreement, analyst feedback weights and the verdict history of the rule.
"""

from __future__ import annotations

import logging
from collections import Counter

from sqlalchemy import select

from backend.context.engine import DEV_SENSITIVE_RULES, ContextFacts, assess_for_alert
from backend.database.models import Alert, AlertVerdict, EntityRisk, NormalizedEvent
from backend.ml.anomaly import get_detector
from backend.risk.entity_risk import EntityRiskManager

log = logging.getLogger("investigation.verdict")

VERDICT_NAMES = {
    "true_positive": "True positive",
    "false_positive": "False positive",
    "expected_behavior": "Expected behavior",
    "needs_review": "Needs review",
}

TP = "true_positive"
FP = "false_positive"
EXP = "expected_behavior"
REVIEW = "needs_review"


def _entity_risk(session, alert: Alert) -> list[dict]:
    """Entity risk profiles for the evidence user + host."""
    out: list[dict] = []
    scope = (alert.evidence or "")[:600]
    user, host = "", alert.host or ""
    import re

    m = re.search(r"\b(?:user|user_name)\s*[:=]\s*([A-Za-z0-9_.\\-]+)", scope)
    if m:
        user = m.group(1)
    manager = EntityRiskManager(session)
    for kind, name in (("user", user), ("device", host)):
        if not name:
            continue
        try:
            prof: EntityRisk | None = manager.profile(kind, name, org=alert.org or "")
        except Exception:
            prof = None
        if prof:
            out.append(
                {
                    "kind": kind,
                    "name": name,
                    "risk_level": prof.risk_level,
                    "risk_score": prof.risk_score,
                    "alerts_count": prof.alerts_count,
                }
            )
    return out


def suggest_verdict(
    session,
    alert: Alert,
    facts: ContextFacts | None = None,
) -> dict:
    """Suggest a verdict for ``alert``. Never writes to the database."""
    scores = {TP: 0.0, FP: 0.0, EXP: 0.0}
    reasons: list[tuple[str, float]] = []

    if facts is None:
        try:
            facts = assess_for_alert(session, alert)
        except Exception:
            log.warning(
                "context assessment failed for alert %s", alert.id, exc_info=True
            )
            facts = None

    # ---- 1) context engine -------------------------------------------------
    if facts is not None:
        if facts.strong_dev_context:
            scores[EXP] += 0.4
            reasons.append(("strong developer-workflow context", 0.4))
        mod = facts.risk_modifier()
        if mod <= 0.6 and alert.rule in DEV_SENSITIVE_RULES:
            scores[EXP] += 0.25
            reasons.append(("risk dampened to %.0f%% by context" % (mod * 100), 0.25))
        unknown = [
            p for p in facts.processes if facts.reputation.get(p.lower()) == "unknown"
        ]
        if unknown and not facts.strong_dev_context:
            scores[TP] += 0.25
            reasons.append(
                (f"unknown process reputation ({', '.join(unknown[:2])})", 0.25)
            )
        if facts.localhost_flows and not facts.strong_dev_context and not unknown:
            scores[EXP] += 0.1

    # ---- 2) rule reputation ------------------------------------------------
    if alert.rule in DEV_SENSITIVE_RULES:
        scores[EXP] += 0.15
        reasons.append(("rule is dev-sensitive", 0.15))

    # ---- 3) severity + confidence ------------------------------------------
    conf = float(alert.confidence or 0.5)
    if alert.severity in ("critical", "high") and conf >= 0.7:
        scores[TP] += 0.3
        reasons.append((f"high severity with confidence {conf:.2f}", 0.3))
    elif alert.severity == "low" and conf < 0.5:
        scores[FP] += 0.25
        reasons.append((f"low severity with weak confidence {conf:.2f}", 0.25))

    # ---- 4) entity risk -----------------------------------------------------
    for prof in _entity_risk(session, alert):
        if prof["risk_level"] in ("HIGH", "CRITICAL"):
            scores[TP] += 0.3
            reasons.append(
                (f"{prof['kind']} '{prof['name']}' at {prof['risk_level']} risk", 0.3)
            )

    # ---- 5) ML agreement -----------------------------------------------------
    ev_ids = [link.event_id for link in alert.events][:40]
    if ev_ids:
        ml_scores = [
            s
            for s in session.scalars(
                select(NormalizedEvent.ml_score).where(
                    NormalizedEvent.id.in_(ev_ids),
                    NormalizedEvent.ml_score.isnot(None),
                )
            ).all()
        ]
        if ml_scores:
            mean_ml = sum(float(s) for s in ml_scores) / len(ml_scores)
            if mean_ml >= 0.6:
                scores[TP] += 0.25
                reasons.append((f"ML anomaly agreement (mean {mean_ml:.2f})", 0.25))
            elif mean_ml <= 0.25:
                scores[FP] += 0.15
                reasons.append(
                    (f"ML finds nothing anomalous (mean {mean_ml:.2f})", 0.15)
                )

    # ---- 6) analyst feedback weights ----------------------------------------
    try:
        weights = get_detector().feedback_weights
        w = float(weights.get(alert.rule, 1.0))
        if w < 0.9:
            scores[EXP if alert.rule in DEV_SENSITIVE_RULES else FP] += 0.2
            reasons.append(
                (f"analysts have down-weighted this rule (weight {w:.2f})", 0.2)
            )
        elif w > 1.1:
            scores[TP] += 0.15
            reasons.append((f"analysts confirmed this rule (weight {w:.2f})", 0.15))
    except Exception:
        pass

    # ---- 7) verdict history of the rule --------------------------------------
    try:
        past = session.scalars(
            select(AlertVerdict.verdict).where(
                AlertVerdict.alert_id.in_(
                    select(Alert.id).where(Alert.rule == alert.rule).limit(300)
                )
            )
        ).all()
        if past:
            tally = Counter(past)
            majority, cnt = tally.most_common(1)[0]
            if majority in (FP, EXP) and cnt >= 2 and cnt / len(past) >= 0.6:
                scores[majority] += 0.2
                reasons.append((f"{cnt} past verdicts on this rule: {majority}", 0.2))
            elif majority == TP and cnt / len(past) >= 0.6:
                scores[TP] += 0.15
                reasons.append(
                    (f"{cnt} past verdicts on this rule: true positive", 0.15)
                )
    except Exception:
        pass

    # ---- 8) correlation chain -------------------------------------------------
    if alert.correlation_id:
        scores[TP] += 0.2
        reasons.append(("part of a correlation chain", 0.2))

    # ---- decision -------------------------------------------------------------
    total = max(1e-6, sum(scores.values()))
    best, best_score = max(scores.items(), key=lambda kv: kv[1])
    strength = min(1.0, total / 0.8)  # overall signal strength
    ratio = best_score / total  # winner dominance
    confidence = round(min(0.95, ratio * (0.35 + 0.65 * strength)), 3)
    if best_score < 0.3:
        verdict = REVIEW
        if not reasons:
            reasons.append(("too little signal for a confident call", 0.0))
        confidence = round(min(0.5, strength), 3)  # unsure means unsure
    else:
        verdict = best

    reasons.sort(key=lambda r: -r[1])
    return {
        "suggested": verdict,
        "label": VERDICT_NAMES[verdict],
        "confidence": round(max(0.2, confidence), 3),
        "reasons": [r[0] for r in reasons[:6]],
        "breakdown": {
            TP: round(scores[TP], 2),
            FP: round(scores[FP], 2),
            EXP: round(scores[EXP], 2),
        },
    }
