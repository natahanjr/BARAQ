"""Confidence scoring for an investigation story.

Combines the rule's built-in confidence, ML agreement on the linked
events, process-tree reconstruction completeness, evidence volume,
context clarity and related-alert corroboration into a single
story-level score with a per-factor breakdown.
"""

from __future__ import annotations

from sqlalchemy import select

from backend.context.engine import ContextFacts
from backend.database.models import Alert, Incident, NormalizedEvent


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


#: Strings in evidence/descriptions that indicate the alert is low-value
#: (developer workflow noise, informational diagnostics) and should
#: suppress incident confidence.
_SUPPRESSION_MARKERS = (
    "strong developer-workflow context",
    "reputation=developer",
    "dev workflow signals",
    "informational",
    "suppressed",
)


def incident_confidence(
    session,
    incident: Incident,
    enrichment: dict | None = None,
) -> dict:
    """Confidence for an incident (Phase-1 roadmap formula):

    confidence = detection_quality + correlation_strength
                 + enrichment_quality - suppression_signals

    Detection quality  = linked alert rule/ML confidence.
    Correlation        = how many distinct alerts / techniques agree.
    Enrichment quality = evidence volume, process-tree completeness,
                         who/where answers available.
    Suppression        = developer-workflow / informational markers.
    """
    alerts = [link.alert for link in incident.alerts if link.alert]

    detection_quality = 0.0
    if alerts:
        detection_quality = 0.65 * _mean([float(a.confidence or 0.5) for a in alerts])
        detection_quality += 0.35 * min(1.0, len(alerts) / 3.0)

    distinct_techniques = len({a.mitre_id for a in alerts if a.mitre_id})
    correlation_strength = min(
        1.0, min(1.0, len(alerts) * 0.30) + min(1.0, distinct_techniques * 0.25)
    )

    enrichment_quality = 0.0
    if enrichment is not None:
        tree = enrichment.get("process_tree") or {}
        six_w = enrichment.get("six_w") or {}
        enrichment_quality = (
            0.30 * min(1.0, (enrichment.get("event_count") or 0) / 8.0)
            + 0.30 * float(tree.get("completeness") or 0.0)
            + 0.20 * min(1.0, (enrichment.get("process_count") or 0) / 3.0)
            + 0.20
            * min(
                1.0, (len(six_w.get("who") or []) + len(six_w.get("where") or [])) / 2.0
            )
        )
    else:
        ev_ids = [link.event_id for alert in alerts for link in alert.events][:200]
        evidence = min(1.0, len(ev_ids) / 8.0)
        enrichment_quality = 0.5 * evidence + 0.5 * min(1.0, len(alerts) / 3.0)

    suppression = 0.0
    corpus = " ".join(
        [incident.description or ""]
        + [(a.evidence or "") + " " + (a.description or "") for a in alerts]
    ).lower()
    if any(marker in corpus for marker in _SUPPRESSION_MARKERS):
        suppression = 0.25

    score = _clamp(
        0.40 * detection_quality
        + 0.30 * correlation_strength
        + 0.30 * enrichment_quality
        - suppression
    )
    score = round(score, 3)

    if score >= 0.75:
        label = "high"
    elif score >= 0.5:
        label = "medium"
    else:
        label = "low"

    return {
        "score": score,
        "label": label,
        "breakdown": [
            {
                "factor": "detection quality",
                "score": round(detection_quality, 3),
                "weight": 0.40,
            },
            {
                "factor": "correlation strength",
                "score": round(correlation_strength, 3),
                "weight": 0.30,
            },
            {
                "factor": "enrichment quality",
                "score": round(enrichment_quality, 3),
                "weight": 0.30,
            },
            {
                "factor": "suppression signals",
                "score": round(-suppression, 3),
                "weight": 0.0,
            },
        ],
    }


def story_confidence(
    session,
    alert: Alert,
    tree: dict,
    related_alerts: list[dict],
    facts: ContextFacts | None = None,
) -> dict:
    """Score how trustworthy the reconstructed story is (0..1)."""
    ev_ids = [link.event_id for link in alert.events][:50]

    evidence_volume = min(1.0, len(ev_ids) / 4.0)

    ml_agreement = 0.0
    if ev_ids:
        ml_scores = [
            float(s)
            for s in session.scalars(
                select(NormalizedEvent.ml_score).where(
                    NormalizedEvent.id.in_(ev_ids),
                    NormalizedEvent.ml_score.isnot(None),
                )
            ).all()
        ]
        ml_agreement = _mean(ml_scores)

    tree_completeness = float(tree.get("completeness") or 0.0)
    seed_found = bool(tree.get("seed_found"))

    rule_confidence = float(alert.confidence or 0.5)

    context_clarity = 0.5
    if facts is not None:
        context_clarity = min(1.0, 0.5 + len(facts.notes()) * 0.12)
        if facts.strong_dev_context or facts.reputation:
            context_clarity = min(1.0, context_clarity + 0.1)

    cluster_signal = min(1.0, len(related_alerts) * 0.2)

    factors = [
        ("evidence volume", evidence_volume, 0.15),
        ("ML agreement", ml_agreement, 0.20),
        (
            "process tree completeness",
            tree_completeness * (0.85 if seed_found else 0.35),
            0.20,
        ),
        ("rule confidence", rule_confidence, 0.15),
        ("context clarity", context_clarity, 0.15),
        ("related alert corroboration", cluster_signal, 0.15),
    ]
    total_weight = sum(w for _, _, w in factors)
    score = sum(v * w for _, v, w in factors) / total_weight
    score = round(max(0.0, min(1.0, score)), 3)

    if score >= 0.75:
        label = "high"
    elif score >= 0.5:
        label = "medium"
    else:
        label = "low"

    return {
        "score": score,
        "label": label,
        "breakdown": [
            {"factor": name, "score": round(value, 3), "weight": weight}
            for name, value, weight in factors
        ],
    }
