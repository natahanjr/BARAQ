"""Phase 5 correlation contract (spec 5.3, 5.4, 5.26-5.28).

A correlation finding connects related behavior groups into an explainable
attack hypothesis. It is NOT an incident, NOT a risk score and NOT a
confirmation of compromise (spec 5.1, 5.69). All values are deterministic
and bounded; titles never overclaim.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Lifecycle (spec 5.31): NEW (born) -> ACTIVE -> QUIET -> CLOSED. A closed
#: correlation never silently absorbs new behavior (spec 5.32).
CORRELATION_STATUSES = ("NEW", "ACTIVE", "QUIET", "CLOSED")

#: Why a finding exists (spec 5.4). The stored `correlation_type` is the
#: primary type contributed by the matching rule; edges carry the supporting
#: relationship types.
CORRELATION_TYPES = (
    "TEMPORAL",
    "ENTITY",
    "HOST_CHAIN",
    "USER_CHAIN",
    "SOURCE_CHAIN",
    "TACTIC_SEQUENCE",
    "TECHNIQUE_SEQUENCE",
    "LATERAL_MOVEMENT",
    "MULTI_STAGE",
)

#: Edge relationship types (spec 5.20).
EDGE_TYPES = (
    "TEMPORAL",
    "SAME_HOST",
    "SAME_USER",
    "SAME_SOURCE",
    "SAME_ACCOUNT",
    "NETWORK_RELATION",
    "DESTINATION_RELATION",
    "TECHNIQUE_TRANSITION",
    "TACTIC_TRANSITION",
    "LATERAL_MOVEMENT",
)

#: Tactic progression phases used by rules (spec 5.18).
PHASES = ("INITIAL_ACCESS", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", "EXECUTION")

#: Technique -> phase map (deterministic, narrow; MITRE is context, never
#: proof of attack - spec 5.17).
TECHNIQUE_PHASES = {
    "T1133": "INITIAL_ACCESS",       # External Remote Services
    "T1190": "INITIAL_ACCESS",       # Exploit Public-Facing Application
    "T1566.001": "INITIAL_ACCESS",   # Phishing: Spearphishing Attachment
    "T1110": "CREDENTIAL_ACCESS",    # Brute Force
    "T1110.001": "CREDENTIAL_ACCESS",
    "T1110.003": "CREDENTIAL_ACCESS",
    "T1110.004": "CREDENTIAL_ACCESS",
    "T1621": "CREDENTIAL_ACCESS",    # Multi-Factor Authentication Request Generation
    "T1021.001": "LATERAL_MOVEMENT", # Remote Desktop Protocol
    "T1021.002": "LATERAL_MOVEMENT", # SMB/Windows Admin Shares
    "T1021.003": "LATERAL_MOVEMENT", # Distributed Component Object Model
    "T1570": "LATERAL_MOVEMENT",     # Lateral Tool Transfer
    "T1059.001": "EXECUTION",        # PowerShell
    "T1059.003": "EXECUTION",        # Windows Command Shell
    "T1059.007": "EXECUTION",        # JavaScript
    "T1047": "EXECUTION",            # Windows Management Instrumentation
    "T1053.005": "EXECUTION",        # Scheduled Task
    "T1486": "IMPACT",               # Data Encrypted for Impact (context only)
}
TECHNIQUE_PHASE_DEFAULT = "UNKNOWN_PHASE"

#: Tactic progression order (spec 5.18): later phases follow earlier ones.
_PHASE_ORDER = {phase: i for i, phase in enumerate(PHASES)}


def phase_of(technique: str | None) -> str:
    if not technique:
        return TECHNIQUE_PHASE_DEFAULT
    return TECHNIQUE_PHASES.get(technique.strip().upper(), TECHNIQUE_PHASE_DEFAULT)


def phases_of(techniques: list | None) -> set[str]:
    return {phase_of(t) for t in (techniques or []) if t}


def is_progression(earlier: str, later: str) -> bool:
    """True when `later` is a later phase in the standard tactic order."""
    a, b = _PHASE_ORDER.get(earlier), _PHASE_ORDER.get(later)
    return a is not None and b is not None and b > a


#: Claims the correlation layer must never emit (spec 5.27): fail loudly if
#: an automatically generated title/description contains any of these.
BANNED_CORRELATION_PHRASES = (
    "confirmed attack",
    "confirmed compromise",
    "attacker confirmed",
    "breach confirmed",
    "apt confirmed",
    "malware confirmed",
    "host compromised",
    "account compromised",
    "confirmed intrusion",
    "proves",
)


#: Deterministic titles per correlation type (spec 5.26) - patterns, not
#: conclusions.
TYPE_TITLES = {
    "TEMPORAL": "Related Activity Within a Shared Time Window",
    "ENTITY": "Related Activity Across Shared Entities",
    "HOST_CHAIN": "Multi-Host Activity Sequence",
    "USER_CHAIN": "User Movement Across Hosts",
    "SOURCE_CHAIN": "Multi-Host Remote Access Pattern",
    "TACTIC_SEQUENCE": "Potential Tactic Progression Sequence",
    "TECHNIQUE_SEQUENCE": "Potential Technique Transition Sequence",
    "LATERAL_MOVEMENT": "Potential Lateral Movement Sequence",
    "MULTI_STAGE": "Potential Multi-Stage Behavioral Sequence",
}

#: Audit actions (spec 5.63).
CORRELATION_ACTIONS = (
    "CORRELATION_CREATED",
    "GROUP_ADDED",
    "EDGE_CREATED",
    "CORRELATION_UPDATED",
    "CORRELATION_QUIET",
    "CORRELATION_CLOSED",
    "CORRELATION_REOPEN_REJECTED",
)


@dataclass
class CorrelationFinding:
    """In-memory correlation finding (spec 5.3). Validated at construction."""

    correlation_id: str
    fingerprint: str
    title: str
    description: str
    status: str
    correlation_type: str
    first_seen: object
    last_seen: object
    member_group_ids: list = field(default_factory=list)
    member_alert_ids: list = field(default_factory=list)
    entities: list = field(default_factory=list)
    hosts: list = field(default_factory=list)
    users: list = field(default_factory=list)
    source_ips: list = field(default_factory=list)
    mitre_tactics: list = field(default_factory=list)
    mitre_techniques: list = field(default_factory=list)
    edges: list = field(default_factory=list)
    observables: dict = field(default_factory=dict)
    confidence: float = 0.0
    highest_severity: str = "low"
    created_at: object = None
    updated_at: object = None
    closed_at: object = None

    def __post_init__(self) -> None:
        if self.status not in CORRELATION_STATUSES:
            raise ValueError(f"invalid correlation status {self.status!r}")
        if self.correlation_type not in CORRELATION_TYPES:
            raise ValueError(f"invalid correlation type {self.correlation_type!r}")
        for edge in self.edges:
            if edge.get("relationship_type") not in EDGE_TYPES:
                raise ValueError(
                    f"invalid edge relationship type "
                    f"{edge.get('relationship_type')!r}"
                )
        title = (self.title or "").lower()
        description = (self.description or "").lower()
        for banned in BANNED_CORRELATION_PHRASES:
            if banned in title or banned in description:
                raise ValueError(
                    f"correlation text contains a banned claim: {banned!r}"
                )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"correlation confidence must be bounded 0..1, got {self.confidence}"
            )
