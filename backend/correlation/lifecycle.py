"""Phase 5 correlation lifecycle (spec 5.31, 5.32, 5.63).

    NEW -> ACTIVE -> QUIET -> CLOSED

NEW: born from the first matching pair, accepting members. ACTIVE: the
primary state while members keep arriving. QUIET: no member for the quiet
timeout, still extendable by an in-window group. CLOSED: terminal - a
closed finding never silently absorbs new groups; a group that would have
joined it records CORRELATION_REOPEN_REJECTED instead (spec 5.32).
"""
from __future__ import annotations

from datetime import datetime

from backend.correlation.models import CorrelationFindingRecord

TRANSITIONS = {
    ("NEW", "ACTIVE"): "CORRELATION_UPDATED",
    ("NEW", "QUIET"): "CORRELATION_QUIET",
    ("ACTIVE", "QUIET"): "CORRELATION_QUIET",
    ("QUIET", "ACTIVE"): "CORRELATION_UPDATED",
    ("QUIET", "CLOSED"): "CORRELATION_CLOSED",
    ("ACTIVE", "CLOSED"): "CORRELATION_CLOSED",
}

ACTIONS = {
    "CORRELATION_CREATED",
    "GROUP_ADDED",
    "EDGE_CREATED",
    "CORRELATION_UPDATED",
    "CORRELATION_QUIET",
    "CORRELATION_CLOSED",
    "CORRELATION_REOPEN_REJECTED",
}


class IllegalTransition(Exception):
    pass


def can_transition(current: str, target: str) -> bool:
    return (current, target) in TRANSITIONS


def transition(current: str, target: str) -> str:
    action = TRANSITIONS.get((current, target))
    if action is None:
        raise IllegalTransition(
            f"{current} -> {target} is not a legal correlation transition"
        )
    return action


def apply_transition(
    finding: CorrelationFindingRecord, target: str, now: datetime
) -> str:
    """Apply a legal lifecycle transition and return the audit action.

    Raises IllegalTransition for anything else - in particular a CLOSED
    finding can never be reopened (spec 5.32).
    """
    action = transition(finding.status, target)
    finding.status = target
    finding.updated_at = now
    if target == "CLOSED":
        finding.closed_at = now
    return action
