"""Phase 6 factor registry (spec 6.9, 6.41).

Every contribution to entity risk comes from a registered factor. A factor
carries its version, description, allowed source types, configured weight
(``RISK_FACTOR_WEIGHTS``), decay policy and the maximum it may ever
contribute. No factor exists outside this registry - "suspicious +25" magic
factors are rejected at the engine boundary (spec 6.43).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.config import (
    RISK_ALERT_SEVERITY_CONTRIBUTIONS,
    RISK_FACTOR_WEIGHTS,
    RISK_MAX_FACTOR_CONTRIBUTION,
    RISK_MODEL_VERSION,
    RISK_REPETITION_CURVE,
)


@dataclass(frozen=True)
class RiskFactorDef:
    """Registered factor definition (spec 6.41)."""

    factor_id: str
    version: str
    description: str
    source_type: str
    weight: float
    decay_policy: str
    maximum_contribution: float

    def as_dict(self) -> dict:
        return {
            "factor_id": self.factor_id,
            "version": self.version,
            "description": self.description,
            "source_type": self.source_type,
            "weight": self.weight,
            "decay_policy": self.decay_policy,
            "maximum_contribution": self.maximum_contribution,
        }


def _weight(factor_id: str, default: float) -> float:
    return float(RISK_FACTOR_WEIGHTS.get(factor_id, default))


def _cap(value: float) -> float:
    return min(value, float(RISK_MAX_FACTOR_CONTRIBUTION))


def _build_registry() -> dict[str, RiskFactorDef]:
    reg: dict[str, RiskFactorDef] = {}

    def add(
        factor_id: str,
        description: str,
        source_type: str,
        decay_policy: str,
        weight: float,
        max_contribution: float | None = None,
    ) -> None:
        reg[factor_id] = RiskFactorDef(
            factor_id=factor_id,
            version="1.0",
            description=description,
            source_type=source_type,
            weight=weight,
            decay_policy=decay_policy,
            maximum_contribution=(
                _cap(max_contribution) if max_contribution is not None else _cap(weight)
            ),
        )

    # RF001: activity reaching the entity from an external source (6.9, 6.11).
    add(
        "RF001_EXTERNAL_ACCESS",
        "External source activity against the entity",
        "behavior_group",
        "half_life",
        _weight("RF001_EXTERNAL_ACCESS", 12),
    )
    # RF002: credential access activity (brute force, logon anomalies).
    add(
        "RF002_CREDENTIAL_ACCESS",
        "Credential access activity involving the entity",
        "behavior_group",
        "half_life",
        _weight("RF002_CREDENTIAL_ACCESS", 14),
    )
    # RF003: the entity participated in lateral movement (6.11: +18).
    add(
        "RF003_LATERAL_MOVEMENT",
        "Entity participated in lateral movement",
        "behavior_group",
        "half_life",
        _weight("RF003_LATERAL_MOVEMENT", 18),
    )
    # RF004: privilege elevation activity.
    add(
        "RF004_PRIVILEGE_ACTIVITY",
        "Privilege escalation activity involving the entity",
        "behavior_group",
        "half_life",
        _weight("RF004_PRIVILEGE_ACTIVITY", 10),
    )
    # RF005: execution activity (script hosts, LOLBins).
    add(
        "RF005_EXECUTION",
        "Execution activity involving the entity",
        "behavior_group",
        "half_life",
        _weight("RF005_EXECUTION", 8),
    )
    # RF006: entity belongs to a multi-stage correlation (6.11: +10 contextual).
    add(
        "RF006_MULTI_STAGE_CORRELATION",
        "Entity is part of a multi-stage correlated sequence",
        "correlation_finding",
        "half_life",
        _weight("RF006_MULTI_STAGE_CORRELATION", 10),
        max_contribution=_weight("RF006_MULTI_STAGE_CORRELATION", 10),
    )
    # RF007: repetition curve (6.13) - never a standalone contribution.
    add(
        "RF007_REPETITION",
        "Repetition scaling for repeated identical evidence",
        "repeat",
        "none",
        _weight("RF007_REPETITION", 0),
        max_contribution=max(float(v) for v in RISK_REPETITION_CURVE),
    )
    # RF008: recent activity bonus (6.11: +8), once per entity.
    add(
        "RF008_RECENCY",
        "Recent activity keeps the risk current",
        "recency",
        "none",
        _weight("RF008_RECENCY", 8),
        max_contribution=_weight("RF008_RECENCY", 8),
    )
    # RF009: alert severity tier (6.9) - once per entity per tier, never
    # per alert (anti risk explosion, spec 6.12).
    add(
        "RF009_ALERT_SEVERITY",
        "Highest alert severity tier observed on the entity",
        "alert",
        "half_life",
        _weight("RF009_ALERT_SEVERITY", 6),
        max_contribution=max(RISK_ALERT_SEVERITY_CONTRIBUTIONS.values()),
    )
    # RF010: behavior group membership (6.9) - one contribution per group,
    # never one per member alert.
    add(
        "RF010_BEHAVIOR_GROUP",
        "Entity belongs to a behavior group",
        "behavior_group",
        "half_life",
        _weight("RF010_BEHAVIOR_GROUP", 10),
    )
    # RF011: persistence technique observed on the entity.
    add(
        "RF011_PERSISTENCE",
        "Persistence technique observed on the entity",
        "behavior_group",
        "half_life",
        _weight("RF011_PERSISTENCE", 10),
    )
    # RF012: defense evasion activity.
    add(
        "RF012_DEFENSE_EVASION",
        "Defense evasion activity involving the entity",
        "behavior_group",
        "half_life",
        _weight("RF012_DEFENSE_EVASION", 8),
    )
    # RF013: entity spans many peers (spread).
    add(
        "RF013_ENTITY_SPREAD",
        "Entity spans many peers in one evidence set",
        "behavior_group",
        "half_life",
        _weight("RF013_ENTITY_SPREAD", 8),
    )
    # RF014: reserved for threat-intel-backed reputation (6.63/6.64): weight
    # 0 by default; never satisfied without a registered reputation source.
    add(
        "RF014_SOURCE_REPUTATION",
        "Reputation of the source (reserved; no external dependency)",
        "reputation",
        "half_life",
        _weight("RF014_SOURCE_REPUTATION", 0),
    )
    return reg


#: Registry snapshot at import time (deterministic).
FACTOR_REGISTRY: dict[str, RiskFactorDef] = _build_registry()

#: Factor id -> factor type (spec 6.9).
FACTOR_ID_TYPES: dict[str, str] = {
    "RF001_EXTERNAL_ACCESS": "EXTERNAL_ACCESS",
    "RF002_CREDENTIAL_ACCESS": "CREDENTIAL_ACCESS",
    "RF003_LATERAL_MOVEMENT": "LATERAL_MOVEMENT",
    "RF004_PRIVILEGE_ACTIVITY": "PRIVILEGE_ACTIVITY",
    "RF005_EXECUTION": "EXECUTION",
    "RF006_MULTI_STAGE_CORRELATION": "CORRELATION",
    "RF007_REPETITION": "ALERT_REPETITION",
    "RF008_RECENCY": "RECENCY",
    "RF009_ALERT_SEVERITY": "ALERT_SEVERITY",
    "RF010_BEHAVIOR_GROUP": "BEHAVIOR_GROUP",
    "RF011_PERSISTENCE": "PERSISTENCE",
    "RF012_DEFENSE_EVASION": "DEFENSE_EVASION",
    "RF013_ENTITY_SPREAD": "ENTITY_SPREAD",
    "RF014_SOURCE_REPUTATION": "SOURCE_REPUTATION",
}


def repetition_curve() -> tuple[float, ...]:
    """Repetition scaling curve (spec 6.13), from config.

    First occurrence gets the full weight, the second half, the third a
    quarter, the fourth and later one-eighth.
    """
    return tuple(float(v) for v in RISK_REPETITION_CURVE)


def get_factor(factor_id: str) -> RiskFactorDef:
    """Registered factor or KeyError (spec 6.43: no magic factors)."""
    if factor_id not in FACTOR_REGISTRY:
        raise KeyError(
            f"unknown risk factor {factor_id!r}; factors must be registered "
            "in backend.risk.registry"
        )
    return FACTOR_REGISTRY[factor_id]


def list_factors() -> list[dict]:
    """All registered factors (spec 6.41)."""
    return [
        FACTOR_REGISTRY[fid].as_dict()
        for fid in sorted(FACTOR_REGISTRY)
    ]


def model_version() -> str:
    return str(RISK_MODEL_VERSION)