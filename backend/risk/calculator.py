"""Phase 6 risk calculator (spec 6.30-6.34).

Pure, deterministic function: ``calculate_risk(factors, now)`` consumes the
factor rows attached to an entity and produces a ``RiskCalculation`` with the
full decomposition (base score, per-factor contributions, decay adjustments,
propagation adjustments, final score, severity, state, confidence). It has no
database access and no hidden state, so the same factors always produce the
same result.
"""

from __future__ import annotations

from datetime import UTC, datetime

from backend.config import (
    RISK_DECAY_HALF_LIFE_HOURS,
    RISK_THRESHOLDS,
)
from backend.risk.contract import RiskCalculation


def decay_factor(age_hours: float, half_life_hours: float | None = None) -> float:
    """Deterministic exponential decay (spec 6.19).

    effective = 0.5^(age_hours / half_life). Fresh evidence keeps (nearly)
    full value; evidence half a life old keeps half; nothing ever goes
    negative - decay is a multiplier, not a subtraction.
    """
    half_life = (
        RISK_DECAY_HALF_LIFE_HOURS if half_life_hours is None else half_life_hours
    )
    if half_life <= 0:
        return 1.0
    if age_hours <= 0:
        return 1.0
    return 0.5 ** (age_hours / half_life)


def severity_for(score: float) -> str:
    """Score -> severity (spec 6.5, 6.8)."""
    if score >= float(RISK_THRESHOLDS["critical"]):
        return "CRITICAL"
    if score >= float(RISK_THRESHOLDS["high"]):
        return "HIGH"
    if score >= float(RISK_THRESHOLDS["medium"]):
        return "MEDIUM"
    if score >= float(RISK_THRESHOLDS["low"]):
        return "LOW"
    return "MINIMAL"


def state_for(score: float) -> str:
    """Score -> state (spec 6.7).

    State bands are the operator-facing action levels:
    NORMAL (0), ELEVATED (>= low), HIGH (>= medium), CRITICAL (>= critical).
    This matches the spec examples: 0 -> NORMAL, 31 -> ELEVATED, 73 -> HIGH.
    STALE is applied by the engine when the calculation is old (6.76).
    """
    if score >= float(RISK_THRESHOLDS["critical"]):
        return "CRITICAL"
    if score >= float(RISK_THRESHOLDS["medium"]):
        return "HIGH"
    if score >= float(RISK_THRESHOLDS["low"]):
        return "ELEVATED"
    return "NORMAL"


def thresholds_crossed(old_score: float, new_score: float) -> list[str]:
    """Severity threshold crossings between two scores (spec 6.44)."""
    old_sev = severity_for(old_score)
    new_sev = severity_for(new_score)
    if old_sev == new_sev:
        return []
    order = ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    lo, hi = sorted((order.index(old_sev), order.index(new_sev)))
    return order[lo + 1 : hi + 1]


def trend_for(
    previous_score: float | None, current_score: float, delta: float = 3.0
) -> str:
    """Trend from consecutive snapshots (spec 6.24): descriptive only."""
    if previous_score is None:
        return "UNKNOWN"
    if current_score - previous_score >= delta:
        return "RISING"
    if previous_score - current_score >= delta:
        return "FALLING"
    return "STABLE"


def calculate_risk(factors: list, now: datetime) -> RiskCalculation:
    """Pure risk calculation over factor rows (spec 6.30-6.32).

    ``factors`` are dicts with keys: factor_id, factor_type, source_type,
    source_id, value, weight, origin, created_at, expires_at, reason,
    evidence. Contributions are value * weight * decay(age); expired factors
    contribute zero but stay counted for provenance. DIRECT contributions are
    the base score; CONTEXTUAL contributions (bounded propagation, 6.27) are
    added separately and capped at 100 overall.
    """
    contributions: list[dict] = []
    decay_adjustments: list[dict] = []
    propagation_adjustments: list[dict] = []
    direct_total = 0.0
    contextual_total = 0.0
    active = 0
    expired = 0
    total = 0

    for f in factors:
        factor_id = f.get("factor_id", "UNKNOWN")
        origin = f.get("origin", "DIRECT")
        value = float(f.get("value", 0.0))
        weight = float(f.get("weight", 1.0))
        created_at = f.get("created_at")
        expires_at = f.get("expires_at")
        age_hours = 0.0
        decay = 1.0
        is_expired = expires_at is not None and expires_at <= now

        if created_at is not None:
            age_hours = max(0.0, (now - created_at).total_seconds() / 3600.0)
            if is_expired:
                decay = 0.0
            else:
                decay = decay_factor(age_hours)
        elif is_expired:
            decay = 0.0

        contribution = round(value * weight * decay, 4)
        total += 1
        if is_expired:
            expired += 1
        else:
            active += 1

        if origin == "CONTEXTUAL":
            contextual_total += contribution
            propagation_adjustments.append(
                {
                    "factor_id": factor_id,
                    "source_type": f.get("source_type", ""),
                    "source_id": f.get("source_id", ""),
                    "origin": origin,
                    "relationship_type": f.get("relationship_type"),
                    "contribution": contribution,
                    "reason": f.get("reason", ""),
                }
            )
        else:
            direct_total += contribution

        contributions.append(
            {
                "factor_id": factor_id,
                "factor_type": f.get("factor_type", ""),
                "source_type": f.get("source_type", ""),
                "source_id": f.get("source_id", ""),
                "origin": origin,
                "value": value,
                "weight": weight,
                "decay_factor": round(decay, 4),
                "contribution": contribution,
                "expired": is_expired,
                "reason": f.get("reason", ""),
                "evidence": f.get("evidence"),
            }
        )
        if decay < 1.0 and not is_expired:
            decay_adjustments.append(
                {
                    "factor_id": factor_id,
                    "source_id": f.get("source_id", ""),
                    "original": round(value * weight, 4),
                    "decay_factor": round(decay, 4),
                    "adjustment": round(value * weight * (1.0 - decay), 4),
                }
            )

    base_score = round(direct_total, 4)
    final_score = round(min(100.0, max(0.0, direct_total + contextual_total)), 4)
    severity = severity_for(final_score)
    state = state_for(final_score)

    total_score = direct_total + contextual_total
    confidence = round(direct_total / total_score, 4) if total_score > 0 else 1.0

    return RiskCalculation(
        base_score=base_score,
        factor_contributions=contributions,
        decay_adjustments=decay_adjustments,
        propagation_adjustments=propagation_adjustments,
        final_score=final_score,
        severity=severity,
        state=state,
        confidence=confidence,
        active_factor_count=active,
        factor_count=total,
        expired_factor_count=expired,
    )


def utcnow() -> datetime:
    return datetime.now(UTC)
