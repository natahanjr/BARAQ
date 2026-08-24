"""Phase 5 correlation rules R001-R009 (spec 5.1, 5.18).

Deterministic rules (version 1.0.0, registry in ``backend/correlation/
rules/__init__.py``): every rule is a pure predicate over group summaries,
never over alert titles and never probabilistic. Pair rules decide whether
two groups may connect; the chain-level rule (R009) decides the finding
type once the sequence grows. There is deliberately NO catch-all rule
(spec 5.74): unrelated activity simply stays uncorrelated.

Rule roster:

    R001 remote_access_to_execution          -> TEMPORAL
    R002 external_access_to_credential_access -> ENTITY
    R003 execution_to_privilege_escalation    -> TECHNIQUE_SEQUENCE
    R004 host_to_host_lateral_movement        -> LATERAL_MOVEMENT
    R005 multi_host_source_chain              -> SOURCE_CHAIN
    R006 user_chain_across_hosts              -> USER_CHAIN
    R007 technique_transition                 -> TECHNIQUE_SEQUENCE
    R008 tactic_progression                   -> TACTIC_SEQUENCE
    R009 multi_stage_sequence                 -> MULTI_STAGE (chain-level)

The chain may also resolve to HOST_CHAIN when it spans three or more
distinct hosts with network/destination relations (documented in
docs/phase5/RULES_POLICY.md).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.correlation.contract import is_progression, phase_of

PHASE_KEYS = ("INITIAL_ACCESS", "CREDENTIAL_ACCESS", "LATERAL_MOVEMENT", "EXECUTION")


def primary_phase(summary: dict) -> str:
    """Deterministic primary phase: the lexicographically first mapped
    technique phase of the group's technique list."""
    techniques = sorted({str(t) for t in (summary.get("techniques") or []) if str(t)})
    for technique in techniques:
        phase = phase_of(technique)
        if phase != "UNKNOWN_PHASE":
            return phase
    return "UNKNOWN_PHASE"


def distinct_host_count(earlier: dict, later: dict) -> int:
    return len(
        {str(h).lower() for h in (earlier.get("hosts") or [])}
        | {str(h).lower() for h in (later.get("hosts") or [])}
    )


def shared(values_a: list, values_b: list) -> set[str]:
    set_a = {str(v).strip().lower() for v in (values_a or []) if str(v).strip()}
    set_b = {str(v).strip().lower() for v in (values_b or []) if str(v).strip()}
    return set_a & set_b


@dataclass(frozen=True)
class CorrelationRule:
    """Pure deterministic rule (spec 5.1). ``matches`` returns the
    "why correlated" reason or None."""

    rule_id: str
    version: str
    title: str
    description: str
    correlation_type: str
    window_key: str
    priority: int
    chain_level: bool = False
    emits_edges: tuple = ()

    def matches(self, earlier: dict, later: dict) -> str | None:
        raise NotImplementedError


@dataclass(frozen=True)
class _R001(CorrelationRule):
    """Remote access followed by execution on the target."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            earlier.get("family") == "authentication"
            and later.get("family") == "execution"
        ):
            return (
                f"rule R001: external access activity involving "
                f"{', '.join(earlier.get('users') or ['an unknown user'])} was "
                f"followed by execution activity"
            )
        return None


@dataclass(frozen=True)
class _R002(CorrelationRule):
    """Same account targeted by external access then credential attempts."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            earlier.get("family") == "authentication"
            and later.get("family") == "authentication"
            and primary_phase(earlier) == "INITIAL_ACCESS"
            and primary_phase(later) == "CREDENTIAL_ACCESS"
            and shared(earlier.get("users"), later.get("users"))
        ):
            return (
                f"rule R002: credential-access activity against the same account "
                f"({', '.join(shared(earlier.get('users'), later.get('users')))}) "
                f"followed external access"
            )
        return None


@dataclass(frozen=True)
class _R003(CorrelationRule):
    """Execution activity followed by credential/privilege activity."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            earlier.get("family") == "execution"
            and primary_phase(later) == "CREDENTIAL_ACCESS"
        ):
            return (
                f"rule R003: execution activity was followed by "
                f"credential/privilege activity ({primary_phase(later)})"
            )
        return None


@dataclass(frozen=True)
class _R004(CorrelationRule):
    """Cross-host movement by the same user/source into lateral technique."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            not shared(earlier.get("hosts"), later.get("hosts"))
            and (
                shared(earlier.get("users"), later.get("users"))
                or shared(earlier.get("sources"), later.get("sources"))
            )
            and primary_phase(later) == "LATERAL_MOVEMENT"
        ):
            return (
                f"rule R004: activity moved from "
                f"{', '.join(earlier.get('hosts') or ['an unknown host'])} to "
                f"{', '.join(later.get('hosts') or ['an unknown host'])} "
                f"with lateral-movement technique {primary_phase(later)}"
            )
        return None


@dataclass(frozen=True)
class _R005(CorrelationRule):
    """Same remote source touching multiple hosts."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            shared(earlier.get("sources"), later.get("sources"))
            and distinct_host_count(earlier, later) >= 2
        ):
            return (
                f"rule R005: source "
                f"{', '.join(shared(earlier.get('sources'), later.get('sources')))} "
                f"touched multiple hosts "
                f"({distinct_host_count(earlier, later)})"
            )
        return None


@dataclass(frozen=True)
class _R006(CorrelationRule):
    """Same user operating from multiple hosts."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        if (
            shared(earlier.get("users"), later.get("users"))
            and distinct_host_count(earlier, later) >= 2
        ):
            return (
                f"rule R006: user "
                f"{', '.join(shared(earlier.get('users'), later.get('users')))} "
                f"operated from multiple hosts "
                f"({distinct_host_count(earlier, later)})"
            )
        return None


@dataclass(frozen=True)
class _R007(CorrelationRule):
    """Technique swap within the same tactic phase (same family)."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        techniques_a = {str(t) for t in (earlier.get("techniques") or [])}
        techniques_b = {str(t) for t in (later.get("techniques") or [])}
        if (
            earlier.get("family") == later.get("family")
            and techniques_a
            and techniques_b
            and techniques_a != techniques_b
            and primary_phase(earlier) == primary_phase(later)
            and primary_phase(earlier) != "UNKNOWN_PHASE"
        ):
            return (
                f"rule R007: technique transition within phase "
                f"{primary_phase(earlier)} "
                f"({', '.join(sorted(techniques_a))} -> "
                f"{', '.join(sorted(techniques_b))})"
            )
        return None


@dataclass(frozen=True)
class _R008(CorrelationRule):
    """Tactic phase progression between two same-family groups."""

    def matches(self, earlier: dict, later: dict) -> str | None:
        techniques_a = {str(t) for t in (earlier.get("techniques") or [])}
        techniques_b = {str(t) for t in (later.get("techniques") or [])}
        if (
            earlier.get("family") == later.get("family")
            and techniques_a
            and techniques_b
            and techniques_a != techniques_b
            and is_progression(primary_phase(earlier), primary_phase(later))
        ):
            return (
                f"rule R008: tactic progression "
                f"{primary_phase(earlier)} -> {primary_phase(later)} "
                f"({', '.join(sorted(techniques_a))} -> "
                f"{', '.join(sorted(techniques_b))})"
            )
        return None


R001 = _R001(
    rule_id="R001",
    version="1.0.0",
    title="Remote Access Followed by Execution",
    description=(
        "Authentication-family behavior followed by execution-family behavior "
        "on a related host within the authentication-to-execution window."
    ),
    correlation_type="TEMPORAL",
    window_key="authentication_to_execution",
    priority=1,
)

R002 = _R002(
    rule_id="R002",
    version="1.0.0",
    title="External Access Followed by Credential Activity",
    description=(
        "Initial-access techniques followed by credential-access techniques "
        "against the same account. Emits SAME_ACCOUNT and TACTIC_TRANSITION."
    ),
    correlation_type="ENTITY",
    window_key="authentication_to_execution",
    priority=2,
    emits_edges=("SAME_ACCOUNT", "TACTIC_TRANSITION"),
)

R003 = _R003(
    rule_id="R003",
    version="1.0.0",
    title="Execution Followed by Privilege/credential Activity",
    description=(
        "Execution-family behavior followed by credential-access phase "
        "behavior within the execution-to-privilege window."
    ),
    correlation_type="TECHNIQUE_SEQUENCE",
    window_key="execution_to_privilege",
    priority=3,
)

R004 = _R004(
    rule_id="R004",
    version="1.0.0",
    title="Host-to-Host Lateral Movement",
    description=(
        "The same user or source operating from a different host with a "
        "lateral-movement technique. Emits LATERAL_MOVEMENT."
    ),
    correlation_type="LATERAL_MOVEMENT",
    window_key="host_to_host_lateral_movement",
    priority=4,
    emits_edges=("LATERAL_MOVEMENT",),
)

R005 = _R005(
    rule_id="R005",
    version="1.0.0",
    title="Multi-Host Source Chain",
    description=(
        "One remote source touching two or more distinct hosts within the "
        "host-to-host window."
    ),
    correlation_type="SOURCE_CHAIN",
    window_key="host_to_host_lateral_movement",
    priority=5,
)

R006 = _R006(
    rule_id="R006",
    version="1.0.0",
    title="User Chain Across Hosts",
    description=(
        "One user operating from two or more distinct hosts within the "
        "host-to-host window."
    ),
    correlation_type="USER_CHAIN",
    window_key="host_to_host_lateral_movement",
    priority=6,
)

R007 = _R007(
    rule_id="R007",
    version="1.0.0",
    title="Technique Transition",
    description=(
        "Technique swap within the same tactic phase, same family. "
        "Emits TECHNIQUE_TRANSITION."
    ),
    correlation_type="TECHNIQUE_SEQUENCE",
    window_key="execution_to_privilege",
    priority=7,
    emits_edges=("TECHNIQUE_TRANSITION",),
)

R008 = _R008(
    rule_id="R008",
    version="1.0.0",
    title="Tactic Progression",
    description=(
        "Tactic phase progression between two same-family groups. "
        "Emits TACTIC_TRANSITION."
    ),
    correlation_type="TACTIC_SEQUENCE",
    window_key="multi_stage",
    priority=8,
    emits_edges=("TACTIC_TRANSITION",),
)

R009 = CorrelationRule(
    rule_id="R009",
    version="1.0.0",
    title="Multi-Stage Sequence",
    description=(
        "Chain-level: a finding of three or more groups spanning two or more "
        "tactic phases resolves to MULTI_STAGE. Never evaluated on a bare pair."
    ),
    correlation_type="MULTI_STAGE",
    window_key="multi_stage",
    priority=9,
    chain_level=True,
)

RULES: tuple[CorrelationRule, ...] = (
    R001,
    R002,
    R003,
    R004,
    R005,
    R006,
    R007,
    R008,
    R009,
)

RULE_BY_ID: dict[str, CorrelationRule] = {rule.rule_id: rule for rule in RULES}
RULES_VERSION = "1.0.0"
