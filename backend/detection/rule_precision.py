"""Rule precision auto-tuning (closed-loop rule quality).

Consumes the FP-analysis ranking and automatically dampens generic rules
whose live precision collapsed, writing the result into the runtime
``detection_tuning`` store (``rule_risk_weights``) so the change applies on
the next detection cycle without restarts. A review-queue entry is kept for
analyst visibility - auto-tuning is reversible with one click.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from backend.api.fp_analysis import analyze as fp_analyze
from backend.detection.tuning import get_raw, set_tuning

logger = logging.getLogger("baraq.rule_tuning")

#: Minimum alert volume before a rule is judged (small samples lie).
MIN_SAMPLES = 8
#: FP-candidate score at which a rule is considered precision-broken.
FP_SCORE_FLOOR = 0.70
#: Risk multiplier applied to broken rules (not zero: never fully blind).
DAMPED_WEIGHT = 0.25


def auto_tune(db: Session, org: str = "") -> dict:
    """Analyze live precision and damp rules below the floor.

    Returns the review queue; also persisted under ``rule_review_queue`` in
    detection_tuning for the settings UI.
    """
    analysis = fp_analyze(db, org=org)
    items = analysis.get("items") or []

    weights_raw = get_raw(db).get("rule_risk_weights") or {}
    weights = dict(weights_raw) if isinstance(weights_raw, dict) else {}

    queue: list[dict] = []
    for item in items:
        rule = item.get("rule") or ""
        total = int(item.get("total") or 0)
        score = float(item.get("fp_candidate_score") or 0.0)
        if not rule or rule == "*":
            continue
        if total < MIN_SAMPLES or score < FP_SCORE_FLOOR:
            continue
        if weights.get(rule) == DAMPED_WEIGHT:
            continue  # already damped
        weights[rule] = DAMPED_WEIGHT
        entry = {
            "rule": rule,
            "fp_score": round(score, 3),
            "total_alerts": total,
            "action": "risk_weight_damped",
            "weight": DAMPED_WEIGHT,
            "since": datetime.now(UTC).isoformat(),
        }
        queue.append(entry)
        logger.info(
            "Rule auto-tuned: %s damped to %.2f weight (fp_score=%.2f, n=%d)",
            rule,
            DAMPED_WEIGHT,
            score,
            total,
        )

    if queue:
        set_tuning(db, "rule_risk_weights", weights, updated_by="auto-precision")
        set_tuning(db, "rule_review_queue", queue, updated_by="auto-precision")

    return {
        "rules_analyzed": len(items),
        "damped": queue,
        "queue_size": len(queue),
    }


def review_queue(db: Session, org: str = "") -> list[dict]:
    """Current auto-tune review queue (for the settings/evaluation UI)."""
    raw = get_raw(db).get("rule_review_queue")
    return raw if isinstance(raw, list) else []
