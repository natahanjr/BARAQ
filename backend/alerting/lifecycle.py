"""Alert lifecycle state machine (spec 3.11).

Explicit transitions only - no arbitrary state jumps. Reopening a closed,
resolved or suppressed alert is an explicit ``REOPEN`` operation.

    OPEN -> ACKNOWLEDGED | IN_PROGRESS | RESOLVED | SUPPRESSED
    ACKNOWLEDGED -> IN_PROGRESS | RESOLVED | SUPPRESSED
    IN_PROGRESS -> RESOLVED | SUPPRESSED
    RESOLVED -> CLOSED | OPEN (explicit reopen)
    CLOSED -> OPEN (explicit reopen)
    SUPPRESSED -> OPEN (explicit reopen)
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerting.contract import ALERT_STATUSES

TRANSITIONS: dict[str, frozenset[str]] = {
    "OPEN": frozenset({"ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"}),
    "ACKNOWLEDGED": frozenset({"IN_PROGRESS", "RESOLVED", "SUPPRESSED"}),
    "IN_PROGRESS": frozenset({"RESOLVED", "SUPPRESSED"}),
    "RESOLVED": frozenset({"CLOSED", "OPEN"}),
    "CLOSED": frozenset({"OPEN"}),
    "SUPPRESSED": frozenset({"OPEN"}),
}


class IllegalTransition(Exception):
    """Raised when a lifecycle transition is not allowed (spec 3.11)."""

    def __init__(self, current: str, target: str):
        self.current = current
        self.target = target
        super().__init__(f"illegal transition {current} -> {target}")


@dataclass(frozen=True)
class Transition:
    action: str
    previous_status: str
    new_status: str


def can_transition(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


def transition(current: str, target: str, *, reopen: bool = False) -> Transition:
    """Validate and describe a transition.

    ``reopen=True`` marks the explicit reopen operation (CLOSED/RESOLVED/
    SUPPRESSED -> OPEN). Raises IllegalTransition for anything else.
    """
    if current not in ALERT_STATUSES:
        raise IllegalTransition(current, target)
    if not can_transition(current, target):
        raise IllegalTransition(current, target)
    if target == "OPEN" and current in ("RESOLVED", "CLOSED", "SUPPRESSED"):
        if not reopen:
            raise IllegalTransition(current, target)
        return Transition(action="REOPENED", previous_status=current, new_status=target)
    return Transition(action=target, previous_status=current, new_status=target)
