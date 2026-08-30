"""Alert workflow state machine.

Formalises the alert lifecycle so analysts and the API share one
transition table: every state change is validated, logged and auditable.

States:
    open            - newly detected, awaiting triage
    acknowledged    - triaged, owner notified/assigned
    investigating   - active investigation in progress
    contained       - containment step applied (quarantine/block)
    resolved        - root cause fixed, awaiting closure
    closed          - fully closed (or auto-stale closed)

Transitions marked with ``escalate`` bump the severity instead of the
state; ``reopen`` moves a closed alert back to open for follow-up.
"""

from __future__ import annotations

#: Allowed transitions: state -> set of reachable states.
TRANSITIONS: dict[str, set[str]] = {
    "open": {"acknowledged", "investigating", "contained", "resolved", "closed"},
    "acknowledged": {"open", "investigating", "contained", "resolved", "closed"},
    "investigating": {"acknowledged", "contained", "resolved", "closed"},
    "contained": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "open"},
    "closed": {"open"},
}

WORKFLOW_STATES = tuple(TRANSITIONS)


def is_valid_state(state: str) -> bool:
    return state in TRANSITIONS


def can_transition(current: str, target: str) -> bool:
    """Whether ``current -> target`` is a legal workflow transition."""
    if current not in TRANSITIONS:
        return False
    if current == target:
        return True
    return target in TRANSITIONS[current]


def next_states(current: str) -> list[str]:
    """Reachable states from ``current`` (for API hints / docs)."""
    if current not in TRANSITIONS:
        return []
    return sorted(TRANSITIONS[current])


#: State categories used by dashboards and dedup logic.
#: Anything except ``closed`` is still an active incident: a repeated
#: finding refreshes the existing alert instead of opening a new one.
ACTIVE_STATES = ("open", "acknowledged", "investigating", "contained", "resolved")
