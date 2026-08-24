"""Alert lifecycle tests (spec 3.11)."""
from __future__ import annotations

import pytest

from backend.alerting.lifecycle import IllegalTransition, can_transition, transition


def test_open_transitions():
    for target in ("ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "SUPPRESSED"):
        assert can_transition("OPEN", target)
    assert not can_transition("OPEN", "CLOSED")


def test_acknowledged_transitions():
    for target in ("IN_PROGRESS", "RESOLVED", "SUPPRESSED"):
        assert can_transition("ACKNOWLEDGED", target)
    assert not can_transition("ACKNOWLEDGED", "OPEN")


def test_in_progress_transitions():
    for target in ("RESOLVED", "SUPPRESSED"):
        assert can_transition("IN_PROGRESS", target)
    assert not can_transition("IN_PROGRESS", "CLOSED")


def test_resolved_transitions():
    assert can_transition("RESOLVED", "CLOSED")
    assert not can_transition("RESOLVED", "IN_PROGRESS")


def test_closed_reopens_only_via_explicit_operation():
    # The transition table allows CLOSED -> OPEN but only as an explicit
    # reopen operation - transition() enforces that constraint.
    assert can_transition("CLOSED", "OPEN")
    with pytest.raises(IllegalTransition):
        transition("CLOSED", "OPEN", reopen=False)
    t = transition("CLOSED", "OPEN", reopen=True)
    assert t.action == "REOPENED"
    assert (t.previous_status, t.new_status) == ("CLOSED", "OPEN")


def test_resolved_and_suppressed_also_need_explicit_reopen():
    for status in ("RESOLVED", "SUPPRESSED"):
        with pytest.raises(IllegalTransition):
            transition(status, "OPEN", reopen=False)
        t = transition(status, "OPEN", reopen=True)
        assert t.action == "REOPENED"
        assert t.new_status == "OPEN"


def test_arbitrary_jumps_rejected():
    with pytest.raises(IllegalTransition):
        transition("OPEN", "CLOSED")
    with pytest.raises(IllegalTransition):
        transition("ACKNOWLEDGED", "OPEN")
    with pytest.raises(IllegalTransition):
        transition("IN_PROGRESS", "ACKNOWLEDGED")
    with pytest.raises(IllegalTransition):
        transition("RESOLVED", "SUPPRESSED")


def test_unknown_status_rejected():
    with pytest.raises(IllegalTransition):
        transition("BOGUS", "OPEN")


def test_normal_transition_describes_action():
    t = transition("OPEN", "ACKNOWLEDGED")
    assert t.action == "ACKNOWLEDGED"
    assert (t.previous_status, t.new_status) == ("OPEN", "ACKNOWLEDGED")