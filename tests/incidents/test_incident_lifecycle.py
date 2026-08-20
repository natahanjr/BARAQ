"""Phase 7 incident lifecycle tests (spec 7.15, 7.48)."""
from __future__ import annotations

import pytest
from backend.incidents.lifecycle import can_transition, transition_status


def test_valid_transitions():
    assert can_transition("NEW", "TRIAGED") is True
    assert can_transition("NEW", "INVESTIGATING") is True
    assert can_transition("TRIAGED", "INVESTIGATING") is True
    assert can_transition("INVESTIGATING", "CONTAINMENT_REQUIRED") is True
    assert can_transition("CONTAINMENT_REQUIRED", "CONTAINED") is True
    assert can_transition("CONTAINED", "RESOLVED") is True
    assert can_transition("RESOLVED", "CLOSED") is True


def test_invalid_transitions():
    assert can_transition("CLOSED", "NEW") is False
    assert can_transition("SUPPRESSED", "NEW") is False
    assert can_transition("RESOLVED", "INVESTIGATING") is False


def test_terminal_states():
    from backend.incidents.lifecycle import is_terminal
    assert is_terminal("CLOSED") is True
    assert is_terminal("SUPPRESSED") is True
    assert is_terminal("NEW") is False


def test_invalid_transition_raises():
    with pytest.raises(Exception):
        transition_status("CLOSED", "NEW")
