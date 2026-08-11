"""Hybrid Risk Scoring Engine (Upgrade Module 5).

Fuses the rule-based detection score (weight 0.6) with the machine-learning
anomaly score (weight 0.4) into a single 0-100 risk score and a risk level.

    Final Risk = 0.6 * RuleScore + 0.4 * MLScore

Risk levels:  LOW (<40) · MEDIUM (40-64) · HIGH (65-84) · CRITICAL (>=85)

The engine is deliberately lightweight: pure math over existing signals, so
it adds no runtime cost on the target laptop.
"""
from __future__ import annotations

import logging

from backend.config import (
    RISK_LEVEL_CRITICAL,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_MEDIUM,
    ML_RULE_WEIGHT,
    ML_DETECTION_WEIGHT,
)

logger = logging.getLogger("baraq.risk")

SEVERITY_BASE = {"info": 15, "low": 30, "medium": 50, "high": 70, "critical": 90}


def rule_score(severity: str, confidence: float, event_count: int = 1) -> float:
    """Rule contribution to the final risk (0-100)."""
    base = SEVERITY_BASE.get(str(severity).lower(), 50)
    confidence = max(0.0, min(1.0, confidence or 0.5))
    count_factor = min(1.5, 1.0 + (max(0, int(event_count) - 1)) * 0.02)
    return round(min(100.0, base * (0.6 + 0.4 * confidence) * count_factor), 2)


def ml_anomaly_score(events: list) -> float:
    """Mean ML anomaly score of the evidence events (0-1 -> 0-100).

    ``events`` is a list of objects with an ``ml_score`` attribute (or dicts).
    Returns 0.0 when no model scores are available.
    """
    scores = []
    for ev in events:
        value = ev.get("ml_score") if isinstance(ev, dict) else getattr(ev, "ml_score", None)
        if value is not None:
            scores.append(float(value))
    if not scores:
        return 0.0
    return round(min(100.0, (sum(scores) / len(scores)) * 100.0), 2)


def hybrid_risk(
    severity: str,
    confidence: float,
    event_count: int,
    anomaly_scores: list,
    rule_weight: float = ML_RULE_WEIGHT,
    ml_weight: float = ML_DETECTION_WEIGHT,
) -> tuple[float, str]:
    """Fuse rule + ML signals into (final_risk_0_100, risk_level)."""
    rule_part = rule_score(severity, confidence, event_count) * rule_weight
    ml_part = ml_anomaly_score(anomaly_scores) * ml_weight
    final = round(min(100.0, rule_part + ml_part), 2)
    return final, risk_level(final)


def risk_level(score: float) -> str:
    """Map a 0-100 score to a risk level."""
    if score >= RISK_LEVEL_CRITICAL:
        return "CRITICAL"
    if score >= RISK_LEVEL_HIGH:
        return "HIGH"
    if score >= RISK_LEVEL_MEDIUM:
        return "MEDIUM"
    return "LOW"


def risk_descriptor(level: str) -> str:
    return {
        "CRITICAL": "Immediate containment required",
        "HIGH": "Prioritized investigation required",
        "MEDIUM": "Monitor and verify",
        "LOW": "Informational / low priority",
    }.get(str(level).upper(), "Unknown")


def compute_rule_score(severity: str, confidence: float, event_count: int = 1) -> float:
    """Evaluation-framework alias for :func:`rule_score`."""
    return rule_score(severity, confidence, event_count)


def compute_hybrid_score(
    rule_score: float,
    ml_scores: list,
    ml_weight: float = ML_DETECTION_WEIGHT,
    rule_weight: float = ML_RULE_WEIGHT,
) -> float:
    """Evaluation-framework entry point: fuse a numeric rule score with ML scores.

    ``rule_score`` is a 0-100 rule-based risk value; ``ml_scores`` is a list of
    per-event anomaly scores (0-1). The weighted blend is renormalized by the
    total weight so a pure rule run (``ml_weight=0``) returns the rule score.
    """
    rule_part = float(rule_score) * rule_weight
    ml_part = ml_anomaly_score(ml_scores) * ml_weight
    total_weight = rule_weight + ml_weight
    if total_weight <= 0:
        return round(min(100.0, float(rule_score)), 2)
    return round(min(100.0, (rule_part + ml_part) / total_weight), 2)
