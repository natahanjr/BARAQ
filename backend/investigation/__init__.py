"""Investigation engine - "one click -> full story".

Orchestrates process-tree reconstruction, related-alert clustering,
automatic verdict generation, confidence scoring, timeline correlation
and context-based risk adjustment for a single alert, so the
investigation page can tell the whole story without the analyst
jumping back to raw events.
"""

from __future__ import annotations

import logging

from backend.context.engine import ContextFacts, assess_for_alert
from backend.database.models import Alert

from .cluster import cluster_related_alerts
from .confidence import story_confidence
from .process_tree import build_process_tree
from .timeline import build_timeline
from .verdict import suggest_verdict

log = logging.getLogger("investigation")


def build_investigation(session, alert: Alert) -> dict:
    """Assemble the full investigation payload for one alert."""
    events = [link.event for link in alert.events]

    tree = build_process_tree(session, events, org=alert.org or "")
    related = cluster_related_alerts(session, alert)
    tree["_related_alerts"] = related  # consumed by the timeline builder

    try:
        facts: ContextFacts | None = assess_for_alert(session, alert)
    except Exception:  # noqa: BLE001
        log.warning("context assessment failed", exc_info=True)
        facts = None

    verdict = suggest_verdict(session, alert, facts)
    confidence = story_confidence(session, alert, tree, related, facts)
    timeline = build_timeline(session, alert, events, tree)
    risk = risk_profile(session, alert, facts)

    tree_out = dict(tree)
    tree_out.pop("_related_alerts", None)

    return {
        "process_tree": tree_out,
        "related_alerts": related,
        "suggested_verdict": verdict,
        "story_confidence": confidence,
        "timeline": timeline,
        "risk_profile": risk,
    }


def risk_profile(session, alert: Alert, facts: ContextFacts | None) -> dict:
    """Context-adjusted risk: original vs adjusted + entity risk scores."""
    modifier = 1.0
    notes: list[str] = []
    if facts is not None:
        modifier = facts.risk_modifier()
        notes = facts.notes()[:6]

    original = float(alert.risk_score or 0.0)
    adjusted = round(original * modifier, 2)

    entities: list[dict] = []
    from .verdict import _entity_risk

    entities = _entity_risk(session, alert)

    return {
        "original_risk": original,
        "adjusted_risk": adjusted,
        "modifier": round(modifier, 3),
        "notes": notes,
        "entities": entities,
    }