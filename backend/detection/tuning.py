"""Runtime detection tuning - risk-weight / threshold tuning.

Analysts adjust risk weights / thresholds from the UI and the
change takes effect immediately. BARAQ stores the same knobs in the
``detection_tuning`` table (see ``DetectionTuning``) so the RBA engine reads
live values instead of restart-time env config. Env vars remain the defaults;
DB overrides win.

Usage::

    from backend.detection.tuning import get_tuning, rule_risk_weights
    weights = rule_risk_weights(db)   # env defaults merged with DB overrides
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import (
    ENTITY_RISK_DECAY_DAYS,
    ENTITY_RISK_LEVEL_CRITICAL,
    ENTITY_RISK_LEVEL_HIGH,
    ENTITY_RISK_LEVEL_MEDIUM,
    ENTITY_RISK_NOTABLE_WINDOW_HOURS,
    RULE_RISK_WEIGHTS,
)
from backend.database.models import DetectionTuning

logger = logging.getLogger("baraq.detection.tuning")

_VALID_KEYS = {
    "rule_risk_weights": dict,
    "risk_thresholds": dict,
    "risk_decay_days": (int, float),
    "risk_notable_window_hours": (int, float),
    "entity_risk_enabled": bool,
}


def _validate(key: str, value: Any) -> Any:
    """Coerce / validate a tuning value before persisting it."""
    if key not in _VALID_KEYS:
        raise ValueError(f"unknown tuning key: {key!r}")
    expected = _VALID_KEYS[key]
    if isinstance(value, dict):
        if expected is dict:
            return {
                str(k): float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else v
                for k, v in value.items()
            }
        raise ValueError(f"tuning key {key!r} expects a mapping")
    if isinstance(expected, tuple):
        try:
            out = float(value) if not isinstance(value, bool) else value
        except (TypeError, ValueError):
            raise ValueError(f"tuning key {key!r} expects a number")
        if key in ("risk_decay_days", "risk_notable_window_hours"):
            out = max(0.1, out)
        return out
    if expected is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "false"):
            return value.strip().lower() == "true"
        raise ValueError(f"tuning key {key!r} expects true/false")
    raise ValueError(f"tuning key {key!r} expects {getattr(expected, '__name__', expected)}")


def get_raw(db: Session) -> dict[str, Any]:
    """All persisted tuning values as {key: value}."""
    rows = db.execute(select(DetectionTuning)).scalars().all()
    return {row.key: row.value for row in rows}


def get_tuning(db: Session) -> dict[str, Any]:
    """The effective, fully-resolved tuning (DB overrides over env defaults)."""
    raw = get_raw(db)
    return {
        "rule_risk_weights": {
            **RULE_RISK_WEIGHTS,
            **(raw.get("rule_risk_weights") or {}),
        },
        "risk_thresholds": {
            "medium": float(raw.get("risk_thresholds", {}).get("medium", ENTITY_RISK_LEVEL_MEDIUM))
            if isinstance(raw.get("risk_thresholds"), dict)
            else float(ENTITY_RISK_LEVEL_MEDIUM),
            "high": float(raw.get("risk_thresholds", {}).get("high", ENTITY_RISK_LEVEL_HIGH))
            if isinstance(raw.get("risk_thresholds"), dict)
            else float(ENTITY_RISK_LEVEL_HIGH),
            "critical": float(raw.get("risk_thresholds", {}).get("critical", ENTITY_RISK_LEVEL_CRITICAL))
            if isinstance(raw.get("risk_thresholds"), dict)
            else float(ENTITY_RISK_LEVEL_CRITICAL),
        },
        "risk_decay_days": float(raw.get("risk_decay_days", ENTITY_RISK_DECAY_DAYS)),
        "risk_notable_window_hours": float(
            raw.get("risk_notable_window_hours", ENTITY_RISK_NOTABLE_WINDOW_HOURS)
        ),
        "entity_risk_enabled": bool(
            raw.get("entity_risk_enabled", True)
        ),
    }


def set_tuning(
    db: Session, key: str, value: Any, updated_by: str = "system"
) -> dict[str, Any]:
    """Persist one tuning value (validated) and return the new effective set."""
    clean = _validate(key, value)
    row = db.execute(select(DetectionTuning).where(DetectionTuning.key == key)).scalar_one_or_none()
    if row is None:
        row = DetectionTuning(key=key, value=clean, updated_by=updated_by)
        db.add(row)
    else:
        row.value = clean
        row.updated_by = updated_by
    db.commit()
    logger.info("Tuning %s set to %s by %s", key, clean, updated_by)
    return get_tuning(db)


def rule_risk_weights(db: Session) -> dict[str, float]:
    """Effective per-rule risk multipliers (DB over env defaults)."""
    return get_tuning(db)["rule_risk_weights"]


def thresholds(db: Session) -> tuple[float, float, float]:
    """(medium, high, critical) entity-risk escalation thresholds."""
    t = get_tuning(db)["risk_thresholds"]
    return float(t["medium"]), float(t["high"]), float(t["critical"])
