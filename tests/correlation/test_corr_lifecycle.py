"""Phase 5 lifecycle tests (spec 5.31, 5.32, 5.63)."""

from datetime import timedelta

import pytest

from backend.correlation.engine import correlate, expire_correlations
from backend.correlation.lifecycle import (
    IllegalTransition,
    apply_transition,
    can_transition,
    transition,
)
from backend.correlation.models import CorrelationFindingRecord
from tests.correlation.helpers import (
    CORR_T0,
    canonical_specs,
    make_groups,
    stored_corr_audit,
    stored_correlations,
)


def test_transition_table_is_exact():
    assert can_transition("NEW", "ACTIVE")
    assert can_transition("NEW", "QUIET")
    assert can_transition("ACTIVE", "QUIET")
    assert can_transition("QUIET", "ACTIVE")
    assert can_transition("QUIET", "CLOSED")
    assert can_transition("ACTIVE", "CLOSED")
    assert not can_transition("CLOSED", "ACTIVE")
    assert not can_transition("NEW", "CLOSED")


def test_transition_action_names():
    assert transition("ACTIVE", "QUIET") == "CORRELATION_QUIET"
    assert transition("QUIET", "CLOSED") == "CORRELATION_CLOSED"
    assert transition("NEW", "ACTIVE") == "CORRELATION_UPDATED"


def test_illegal_transition_rejected():
    with pytest.raises(IllegalTransition):
        transition("CLOSED", "ACTIVE")


def test_quiet_then_close_lifecycle(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    assert finding.status in ("NEW", "ACTIVE")

    expire_correlations(db, now=CORR_T0 + timedelta(hours=3))
    finding = stored_correlations(db)[0]
    assert finding.status == "QUIET"
    assert finding.closed_at is None

    expire_correlations(db, now=CORR_T0 + timedelta(hours=6))
    finding = stored_correlations(db)[0]
    assert finding.status == "CLOSED"
    assert finding.closed_at is not None

    actions = {e.action for e in stored_corr_audit(db)}
    assert "CORRELATION_QUIET" in actions
    assert "CORRELATION_CLOSED" in actions


def test_closed_finding_never_silently_reopens(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    expire_correlations(db, now=CORR_T0 + timedelta(hours=6))
    closed_id = stored_correlations(db)[0].correlation_id
    assert stored_correlations(db)[0].status == "CLOSED"

    # New matching activity hours later.
    make_groups(
        db,
        [
            {
                "detector_id": "D002",
                "host": "10.0.0.9",
                "user": "u-r1",
                "source_ip": "198.51.100.9",
                "mitre": "T1110",
                "minutes_ago": 0,
                "destination_ip": "10.0.0.8",
            },
            {
                "detector_id": "D002",
                "host": "10.0.0.8",
                "user": "u-r1",
                "source_ip": "198.51.100.9",
                "mitre": "T1110",
                "minutes_ago": 1,
                "destination_ip": "10.0.0.7",
            },
        ],
        now=CORR_T0 + timedelta(hours=8),
    )
    correlate(db, now=CORR_T0 + timedelta(hours=8))

    findings = stored_correlations(db)
    old = next(f for f in findings if f.correlation_id == closed_id)
    assert old.status == "CLOSED"
    assert "CORRELATION_REOPEN_REJECTED" in {
        e.action for e in stored_corr_audit(db) if e.correlation_id == closed_id
    }
    # A NEW finding exists for the new episode instead.
    assert len(findings) == 2
    assert findings[1].status in ("NEW", "ACTIVE")


def test_finding_model_rejects_reopen_transition():

    finding = CorrelationFindingRecord(status="CLOSED")
    with pytest.raises(IllegalTransition):
        apply_transition(finding, "ACTIVE", CORR_T0)
