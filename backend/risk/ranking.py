"""Professional Alert Ranking Engine.

Implements a deterministic, explainable, multi-factor risk ranking system
that answers: "Which security incident deserves the analyst's attention
first, and exactly why?"

Formula:
    risk_score =
        severity_weight
        × confidence_multiplier
        × asset_criticality_multiplier
        × correlation_multiplier
        × recency_multiplier
        × repeat_dampener

Each component is separately stored for full explainability.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Sequence

logger = logging.getLogger("baraq.risk.ranking")


# ── Severity Weights (Section 1) ─────────────────────────────────────
SEVERITY_WEIGHT: dict[str, float] = {
    "healthy": 0.00,
    "info": 0.00,
    "low": 0.05,
    "medium": 0.10,
    "high": 0.30,
    "critical": 1.00,
}


def severity_weight(severity: str) -> float:
    """Return the base severity weight.  Never returns negative."""
    return SEVERITY_WEIGHT.get(str(severity).lower(), 0.10)


# ── Confidence Multiplier (Section 2) ────────────────────────────────
def confidence_multiplier(confidence: float | None) -> float:
    """Map detection confidence to a ranking multiplier."""
    c = max(0.0, min(1.0, confidence or 0.0))
    if c < 0.40:
        return 0.50
    if c < 0.70:
        return 0.75
    if c < 0.90:
        return 1.00
    return 1.25


# ── Asset Criticality Multiplier (Section 3) ─────────────────────────
ASSET_MULTIPLIER: dict[str, float] = {
    "low": 0.75,
    "normal": 1.00,
    "important": 1.50,
    "critical": 2.00,
}


def asset_criticality_multiplier(criticality: str | None) -> float:
    """Map asset criticality label to a ranking multiplier."""
    if not criticality:
        return 1.00
    return ASSET_MULTIPLIER.get(str(criticality).lower(), 1.00)


# ── Correlation Multiplier (Section 4) ───────────────────────────────
def correlation_multiplier(correlated_count: int, is_attack_chain: bool = False) -> float:
    """Map the number of related alerts to a ranking multiplier.

    ``correlated_count`` is the total number of alerts in the correlation
    group including the alert itself.
    """
    if is_attack_chain:
        return 2.50
    if correlated_count >= 5:
        return 2.00
    if correlated_count >= 3:
        return 1.50
    if correlated_count >= 2:
        return 1.25
    return 1.00


# ── Recency / Time Decay (Section 5) ─────────────────────────────────
def recency_multiplier(last_seen: datetime | None, now: datetime | None = None) -> float:
    """Apply time decay based on how recently the alert was seen.

    The decay is deterministic and testable.
    """
    if last_seen is None:
        return 0.50  # unknown age → moderate dampening
    if now is None:
        now = datetime.now(timezone.utc)
    # Ensure both are timezone-aware
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    age = max(timedelta(0), now - last_seen)
    minutes = age.total_seconds() / 60.0
    if minutes <= 15:
        return 1.00
    if minutes <= 60:
        return 0.90
    if minutes <= 360:  # 6 hours
        return 0.70
    if minutes <= 1440:  # 24 hours
        return 0.50
    if minutes <= 4320:  # 3 days
        return 0.25
    return 0.10


# ── Repeated Alert Dampening (Section 8) ─────────────────────────────
def repeat_dampener(occurrence: int) -> float:
    """Dampen repeated identical alerts to prevent flooding.

    ``occurrence`` is 1-based (1 = first occurrence).
    """
    if occurrence <= 1:
        return 1.00
    if occurrence <= 5:
        return 0.75
    if occurrence <= 10:
        return 0.50
    return 0.25


# ── Risk Level from Score ────────────────────────────────────────────
def risk_level_from_score(score: float) -> str:
    """Map a risk_score to a human-readable level."""
    if score >= 2.0:
        return "CRITICAL"
    if score >= 1.0:
        return "HIGH"
    if score >= 0.3:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "HEALTHY"


# ── Explainability Dataclass (Section 10) ────────────────────────────
@dataclass
class RiskBreakdown:
    """Full decomposition of a risk score for analyst explainability."""

    risk_score: float = 0.0
    severity: str = "LOW"
    severity_weight: float = 0.0
    confidence: float = 0.5
    confidence_multiplier: float = 1.0
    asset_criticality: str = "NORMAL"
    asset_multiplier: float = 1.0
    correlation_level: str = "single"
    correlated_alerts: int = 1
    correlation_multiplier: float = 1.0
    is_attack_chain: bool = False
    recency_minutes: float = 0.0
    recency_multiplier: float = 1.0
    occurrence: int = 1
    repeat_dampener: float = 1.0
    risk_level: str = "LOW"

    def to_dict(self) -> dict:
        return asdict(self)

    def explanation(self) -> str:
        """Human-readable one-line explanation."""
        parts = [
            f"Severity: {self.severity.upper()}        ×{self.severity_weight:.2f}",
            f"Confidence: {self.confidence:.0%}      ×{self.confidence_multiplier:.2f}",
            f"Asset: {self.asset_criticality.upper()}      ×{self.asset_multiplier:.2f}",
        ]
        corr_label = (
            "Attack chain" if self.is_attack_chain
            else f"{self.correlated_alerts} alert{'s' if self.correlated_alerts != 1 else ''}"
        )
        parts.append(f"Correlation: {corr_label} ×{self.correlation_multiplier:.2f}")
        if self.recency_minutes < 60:
            parts.append(f"Recency: {self.recency_minutes:.0f} minutes   ×{self.recency_multiplier:.2f}")
        else:
            hours = self.recency_minutes / 60
            parts.append(f"Recency: {hours:.1f} hours     ×{self.recency_multiplier:.2f}")
        if self.occurrence > 1:
            parts.append(f"Repeat: #{self.occurrence}              ×{self.repeat_dampener:.2f}")
        parts.append(f"\nRisk Score: {self.risk_score:.3f}")
        return "\n".join(parts)


# ── Core Ranking Function (Section 6) ────────────────────────────────
def compute_risk_score(
    *,
    severity: str,
    confidence: float | None = None,
    asset_criticality: str | None = None,
    correlated_alerts: int = 1,
    is_attack_chain: bool = False,
    last_seen: datetime | None = None,
    occurrence: int = 1,
    now: datetime | None = None,
) -> RiskBreakdown:
    """Compute the professional risk score for an alert or incident.

    Each multiplier is stored in the returned RiskBreakdown for full
    explainability (Section 10).
    """
    sw = severity_weight(severity)
    cm = confidence_multiplier(confidence)
    acm = asset_criticality_multiplier(asset_criticality)
    crm = correlation_multiplier(correlated_alerts, is_attack_chain)
    rm = recency_multiplier(last_seen, now)
    rd = repeat_dampener(occurrence)

    raw = sw * cm * acm * crm * rm * rd
    # Clamp to non-negative, round to 3 decimal places
    score = round(max(0.0, raw), 3)
    level = risk_level_from_score(score)

    # Determine correlation label
    if is_attack_chain:
        corr_label = "attack_chain"
    elif correlated_alerts >= 5:
        corr_label = "5+"
    elif correlated_alerts >= 3:
        corr_label = "3-4"
    elif correlated_alerts >= 2:
        corr_label = "2"
    else:
        corr_label = "single"

    breakdown = RiskBreakdown(
        risk_score=score,
        severity=str(severity).lower(),
        severity_weight=sw,
        confidence=max(0.0, min(1.0, confidence or 0.0)),
        confidence_multiplier=cm,
        asset_criticality=str(asset_criticality or "normal").lower(),
        asset_multiplier=acm,
        correlation_level=corr_label,
        correlated_alerts=max(1, correlated_alerts),
        correlation_multiplier=crm,
        is_attack_chain=is_attack_chain,
        recency_minutes=(
            max(0.0, (datetime.now(timezone.utc) - last_seen.replace(tzinfo=timezone.utc)).total_seconds() / 60.0)
            if last_seen
            else 0.0
        ),
        recency_multiplier=rm,
        occurrence=max(1, occurrence),
        repeat_dampener=rd,
        risk_level=level,
    )
    return breakdown


# ── Batch Ranking ────────────────────────────────────────────────────
def rank_alerts(
    alerts: Sequence[dict],
    now: datetime | None = None,
) -> list[dict]:
    """Rank a list of alerts and return them sorted by risk_score DESC.

    Each alert dict must contain at minimum:
        severity, confidence, created_at/updated_at

    Optional keys: asset_criticality, correlated_alerts, is_attack_chain,
                   occurrence.

    Returns the same dicts with ``risk_score`` and ``risk_breakdown`` added,
    sorted by risk_score descending.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    scored = []
    for alert in alerts:
        last_seen = (
            alert.get("updated_at")
            or alert.get("created_at")
            or alert.get("last_seen")
        )
        if isinstance(last_seen, str):
            try:
                last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            except ValueError:
                last_seen = None

        breakdown = compute_risk_score(
            severity=alert.get("severity", "medium"),
            confidence=alert.get("confidence"),
            asset_criticality=alert.get("asset_criticality"),
            correlated_alerts=int(alert.get("correlated_alerts", 1)),
            is_attack_chain=bool(alert.get("is_attack_chain", False)),
            last_seen=last_seen,
            occurrence=int(alert.get("occurrence", 1)),
            now=now,
        )
        alert["risk_score"] = breakdown.risk_score
        alert["risk_level"] = breakdown.risk_level
        alert["risk_breakdown"] = breakdown.to_dict()
        scored.append(alert)

    # Sort: risk_score DESC, confidence DESC, severity DESC, last_seen DESC
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "healthy": 0}
    scored.sort(
        key=lambda a: (
            a["risk_score"],
            a.get("confidence", 0),
            severity_order.get(str(a.get("severity", "")).lower(), 0),
            a.get("updated_at") or a.get("created_at") or "",
        ),
        reverse=True,
    )
    return scored


# ── Healthy State (Section 11) ───────────────────────────────────────
def healthy_score() -> RiskBreakdown:
    """Return a zero-score breakdown for the healthy state."""
    return RiskBreakdown(
        risk_score=0.0,
        severity="healthy",
        severity_weight=0.0,
        confidence=0.0,
        confidence_multiplier=1.0,
        asset_criticality="normal",
        asset_multiplier=1.0,
        correlation_level="single",
        correlated_alerts=0,
        correlation_multiplier=1.0,
        is_attack_chain=False,
        recency_minutes=0.0,
        recency_multiplier=1.0,
        occurrence=1,
        repeat_dampener=1.0,
        risk_level="HEALTHY",
    )
