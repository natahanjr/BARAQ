"""Phase 7 incident lifecycle transitions (spec 7.15, 7.16, 7.17, 7.21, 7.48)."""

from __future__ import annotations

from datetime import UTC, datetime

from backend.incidents.contract import INCIDENT_STATES, INCIDENT_TRANSITIONS


class InvalidTransitionError(Exception):
    pass


def can_transition(current: str, target: str) -> bool:
    return target in INCIDENT_TRANSITIONS.get(current, ())


def transition_status(
    current: str,
    target: str,
    actor: str = "system",
    reason: str | None = None,
) -> dict:
    if not can_transition(current, target):
        raise InvalidTransitionError(
            f"invalid incident transition {current!r} -> {target!r}"
        )
    return {
        "old_status": current,
        "new_status": target,
        "actor": actor,
        "reason": reason,
        "transitioned_at": datetime.now(UTC).isoformat(),
    }


def is_terminal(status: str) -> bool:
    return status in ("CLOSED", "SUPPRESSED")


def active_statuses() -> tuple[str, ...]:
    return tuple(s for s in INCIDENT_STATES if s not in ("CLOSED", "SUPPRESSED"))
