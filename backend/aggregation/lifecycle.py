"""Phase 4 group lifecycle (spec 4.15, 4.16, 4.29, 4.30).

    ACTIVE -> QUIET -> CLOSED

ACTIVE: accepting members. QUIET: no activity for the quiet timeout, still
reopenable by a new in-window alert. CLOSED: terminal - a new matching
episode creates a NEW group; the old group records GROUP_REOPEN_REJECTED.

Groups never silently absorb new alerts after closing (4.16), and an
outside-window alert against a still-live group closes it first so the new
episode gets its own group (4.14).
"""
from __future__ import annotations

from datetime import datetime

from backend.aggregation.models import BehaviorGroupRecord

TRANSITIONS = {
    ("ACTIVE", "QUIET"): "GROUP_QUIET",
    ("QUIET", "ACTIVE"): "GROUP_REACTIVATED",
    ("QUIET", "CLOSED"): "GROUP_CLOSED",
    ("ACTIVE", "CLOSED"): "GROUP_CLOSED",
}

ACTIONS = {
    "GROUP_CREATED",
    "ALERT_ADDED",
    "GROUP_UPDATED",
    "GROUP_QUIET",
    "GROUP_REACTIVATED",
    "GROUP_CLOSED",
    "GROUP_REOPEN_REJECTED",
}


class IllegalTransition(Exception):
    pass


def can_transition(current: str, target: str) -> bool:
    return (current, target) in TRANSITIONS


def transition(current: str, target: str) -> str:
    action = TRANSITIONS.get((current, target))
    if action is None:
        raise IllegalTransition(f"{current} -> {target} is not a legal group transition")
    return action


def apply_transition(group: BehaviorGroupRecord, target: str, now: datetime) -> str:
    """Apply a legal lifecycle transition to a stored group and return the
    audit action. Raises IllegalTransition for anything else."""
    action = transition(group.status, target)
    group.status = target
    group.updated_at = now
    if target == "CLOSED":
        group.closed_at = now
    return action