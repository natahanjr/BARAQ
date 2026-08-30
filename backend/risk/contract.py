"""Phase 6 entity risk contract (spec 6.4, 6.5, 6.7, 6.30-6.32).

Entity risk is an accumulated, explainable, time-aware state - never a
probability of compromise, never alert severity, never a second detection
engine (spec 6.83). All values are deterministic and bounded; scores are
0-100 and every contribution traces to concrete evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

#: Entity types (spec 6.2).
ENTITY_TYPES = ("HOST", "USER", "ACCOUNT", "SOURCE_IP", "DESTINATION_IP", "PROCESS")

#: Severities (spec 6.5) - derived from score thresholds (config), never
#: hardcoded elsewhere.
RISK_SEVERITIES = ("MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Risk states (spec 6.7): NORMAL/ELEVATED/HIGH/CRITICAL derived from the
#: current score band, STALE when the last calculation is old.
RISK_STATES = ("NORMAL", "ELEVATED", "HIGH", "CRITICAL", "STALE")

#: Trend (spec 6.24): descriptive only, never a factor.
RISK_TRENDS = ("RISING", "STABLE", "FALLING", "UNKNOWN")

#: Contribution origin (spec 6.81): every contribution is DIRECT (evidence
#: directly involving the entity) or CONTEXTUAL (bounded propagation).
ORIGINS = ("DIRECT", "CONTEXTUAL")

#: Evidence kinds the engine accepts (spec 6.1).
EVIDENCE_KINDS = ("DETECTION", "ALERT", "BEHAVIOR_GROUP", "CORRELATION_FINDING")

#: Factor types (spec 6.9).
FACTOR_TYPES = (
    "ALERT_SEVERITY",
    "ALERT_REPETITION",
    "BEHAVIOR_GROUP",
    "CORRELATION",
    "LATERAL_MOVEMENT",
    "EXTERNAL_ACCESS",
    "CREDENTIAL_ACCESS",
    "PRIVILEGE_ACTIVITY",
    "PERSISTENCE",
    "EXECUTION",
    "DEFENSE_EVASION",
    "RECENCY",
    "SOURCE_REPUTATION",
    "ENTITY_SPREAD",
)

#: Audit actions (spec 6.44).
RISK_ACTIONS = (
    "RISK_CREATED",
    "RISK_UPDATED",
    "FACTOR_ADDED",
    "FACTOR_EXPIRED",
    "FACTOR_REMOVED",
    "RISK_RECALCULATED",
    "RISK_STATE_CHANGED",
    "RISK_THRESHOLD_CROSSED",
    "RISK_MODEL_CHANGED",
    "RISK_CALCULATION_FAILED",
)

#: Claims the risk layer must never emit (spec 6.43, 6.83): risk is
#: concentration of evidence, never a verdict of compromise.
BANNED_RISK_PHRASES = (
    "compromised",
    "breached",
    "is an attacker",
    "definitely malicious",
    "confirmed attack",
    "confirmed intrusion",
    "proves",
)

#: Deterministic explanation titles per severity.
SEVERITY_TITLES = {
    "MINIMAL": "No Significant Risk Evidence",
    "LOW": "Low Risk Evidence Concentration",
    "MEDIUM": "Elevated Risk Evidence Concentration",
    "HIGH": "High Risk Evidence Concentration",
    "CRITICAL": "Critical Risk Evidence Concentration",
}


@dataclass
class RiskCalculation:
    """Deterministic output of ``calculate_risk`` (spec 6.30-6.32)."""

    base_score: float
    factor_contributions: list = field(default_factory=list)
    decay_adjustments: list = field(default_factory=list)
    propagation_adjustments: list = field(default_factory=list)
    final_score: float = 0.0
    severity: str = "MINIMAL"
    state: str = "NORMAL"
    confidence: float = 1.0
    risk_model_version: str = "1.0.0"
    active_factor_count: int = 0
    factor_count: int = 0
    expired_factor_count: int = 0

    def __post_init__(self) -> None:
        if not 0.0 <= self.final_score <= 100.0:
            raise ValueError(
                f"risk score must be bounded 0..100, got {self.final_score}"
            )
        if self.severity not in RISK_SEVERITIES:
            raise ValueError(f"invalid risk severity {self.severity!r}")
        if self.state not in RISK_STATES:
            raise ValueError(f"invalid risk state {self.state!r}")


@dataclass
class EntityRisk:
    """In-memory entity risk state (spec 6.4). Validated at construction."""

    risk_id: str
    entity_type: str
    entity_id: str
    entity_name: str
    score: float
    severity: str
    state: str
    confidence: float
    trend: str
    peak_score: float
    peak_at: object
    first_seen: object
    last_seen: object
    active_factor_count: int
    evidence_count: int
    alert_count: int
    group_count: int
    correlation_count: int
    risk_model_version: str
    created_at: object = None
    updated_at: object = None
    calculated_at: object = None

    def __post_init__(self) -> None:
        if self.entity_type not in ENTITY_TYPES:
            raise ValueError(f"invalid entity type {self.entity_type!r}")
        if not 0.0 <= self.score <= 100.0:
            raise ValueError(
                f"entity risk score must be bounded 0..100, got {self.score}"
            )
        if self.severity not in RISK_SEVERITIES:
            raise ValueError(f"invalid risk severity {self.severity!r}")
        if self.state not in RISK_STATES:
            raise ValueError(f"invalid risk state {self.state!r}")
        if self.trend not in RISK_TRENDS:
            raise ValueError(f"invalid risk trend {self.trend!r}")
