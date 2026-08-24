"""Phase 5 pair relationship detection (spec 5.20-5.22).

A pair of behavior groups is related when they share at least
``CORRELATION_MIN_RELATIONSHIPS`` relationship types. Relationship types
are deterministic functions of the group summaries - never of alert
titles. Technique transitions are only claimed for same-family pairs
(MITRE is context, not proof - spec 5.17); the canonical 5.70 example
therefore keeps exactly SAME_USER / SAME_SOURCE / TEMPORAL /
DESTINATION_RELATION / LATERAL_MOVEMENT.
"""
from __future__ import annotations

from datetime import datetime

import backend.config as config
from backend.correlation.contract import (
    EDGE_TYPES,
    is_progression,
    phase_of,
)

#: relationship type -> edge strength weight category (spec 5.21).
_RELATIONSHIP_WEIGHT_CATEGORY = {
    "SAME_HOST": "host",
    "SAME_USER": "user",
    "SAME_ACCOUNT": "user",
    "SAME_SOURCE": "source",
    "TEMPORAL": "time",
    "TECHNIQUE_TRANSITION": "technique",
    "TACTIC_TRANSITION": "technique",
    #: Qualitative signals: counted as shared factors for confidence but
    #: never in the strength sum (no inflated scores).
    "NETWORK_RELATION": None,
    "DESTINATION_RELATION": None,
    "LATERAL_MOVEMENT": None,
}


def edge_strength(relationship_types: list[str]) -> float:
    """Deterministic edge strength (spec 5.21): sum of the weight
    categories actually shared, each category counted once, capped at 1.000.
    A correlation strength - never a risk score."""
    categories = {
        category
        for reltype in relationship_types
        if (category := _RELATIONSHIP_WEIGHT_CATEGORY.get(reltype)) is not None
    }
    weights = config.CORRELATION_EDGE_WEIGHTS
    total = sum(weights[category] for category in categories if category in weights)
    return round(min(1.0, total), 4)


def _set_of(values) -> set[str]:
    return {str(v).strip().lower() for v in (values or []) if str(v).strip()}


def pair_relationships(
    earlier: dict,
    later: dict,
    *,
    window_key: str,
    within_window: bool,
) -> dict:
    """Relationship bundle between two group summaries.

    Returns ``{"types": [...], "shared": {...}, "time_delta_seconds": ...}``.
    ``types`` is sorted so every downstream output is deterministic.
    """
    from backend.correlation.windows import within_window as window_check

    earlier_hosts = _set_of(earlier.get("hosts"))
    later_hosts = _set_of(later.get("hosts"))
    earlier_users = _set_of(earlier.get("users"))
    later_users = _set_of(later.get("users"))
    earlier_sources = _set_of(earlier.get("sources"))
    later_sources = _set_of(later.get("sources"))
    earlier_dests = _set_of(earlier.get("destinations"))
    later_dests = _set_of(later.get("destinations"))

    shared_hosts = earlier_hosts & later_hosts
    shared_users = earlier_users & later_users
    shared_sources = earlier_sources & later_sources
    shared_dests = earlier_dests & later_dests

    types: list[str] = []
    if shared_hosts:
        types.append("SAME_HOST")
    if shared_users:
        types.append("SAME_USER")
    if shared_sources:
        types.append("SAME_SOURCE")
    #: Destination relation: the earlier activity pointed at a host the
    #: later group acted on (e.g. brute force then lateral into the target).
    if earlier_dests & later_hosts:
        types.append("DESTINATION_RELATION")
    #: Network relation: both groups targeted the same destination.
    if shared_dests:
        types.append("NETWORK_RELATION")

    temporal = window_check(
        earlier["first_seen"], later["first_seen"], window_key
    ) if within_window is None else within_window
    if temporal:
        types.append("TEMPORAL")

    #: Technique transitions (spec 5.17): only within a family - MITRE
    #: technique change is context for same-family progressions, never a
    #: cross-family claim.
    earlier_techniques = _set_of(earlier.get("techniques"))
    later_techniques = _set_of(later.get("techniques"))
    if (
        earlier.get("family") == later.get("family")
        and earlier_techniques
        and later_techniques
        and earlier_techniques != later_techniques
    ):
        earlier_phase = phase_of(next(iter(earlier_techniques)))
        later_phase = phase_of(next(iter(later_techniques)))
        if earlier_phase != "UNKNOWN_PHASE" and later_phase != "UNKNOWN_PHASE":
            if earlier_phase == later_phase:
                types.append("TECHNIQUE_TRANSITION")
            elif is_progression(earlier_phase, later_phase):
                types.append("TACTIC_TRANSITION")

    types = [t for t in EDGE_TYPES if t in types]
    delta = (
        int((later["first_seen"] - earlier["first_seen"]).total_seconds())
        if isinstance(later["first_seen"], datetime)
        and isinstance(earlier["first_seen"], datetime)
        else None
    )
    return {
        "types": types,
        "shared": {
            "hosts": sorted(shared_hosts),
            "users": sorted(shared_users),
            "sources": sorted(shared_sources),
            "destinations": sorted(shared_dests),
        },
        "time_delta_seconds": delta,
    }


def meets_minimum(rel: dict) -> bool:
    """Contextual relationship floor (spec 5.22): at least two
    relationships must exist before an edge is claimed."""
    return len(rel["types"]) >= config.CORRELATION_MIN_RELATIONSHIPS
