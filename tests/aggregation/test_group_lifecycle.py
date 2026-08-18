"""Phase 4 lifecycle tests (spec 4.15, 4.16, 4.29, 4.30)."""
from datetime import timedelta

import pytest

from backend.aggregation.engine import expire_groups, process_alerts
from backend.aggregation.lifecycle import IllegalTransition, can_transition, transition

from tests.aggregation.helpers import GROUP_T0, make_alerts, stored_group_audit, stored_groups


def test_transition_table():
    assert can_transition("ACTIVE", "QUIET")
    assert can_transition("QUIET", "ACTIVE")
    assert can_transition("QUIET", "CLOSED")
    assert can_transition("ACTIVE", "CLOSED")
    assert not can_transition("CLOSED", "ACTIVE")
    assert not can_transition("ACTIVE", "OPEN")
    with pytest.raises(IllegalTransition):
        transition("CLOSED", "ACTIVE")
    with pytest.raises(IllegalTransition):
        transition("ACTIVE", "OPEN")


def test_expiration_quiet_then_closed(db):
    """10:10 last alert -> QUIET at +30min -> CLOSED at +60min (4.15)."""
    alerts = make_alerts(db, [dict(minutes_ago=10.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]

    expire_groups(db, now=GROUP_T0 + timedelta(minutes=20))
    assert stored_groups(db)[0].status == "ACTIVE"

    expire_groups(db, now=GROUP_T0 + timedelta(minutes=31))
    assert stored_groups(db)[0].status == "QUIET"

    expire_groups(db, now=GROUP_T0 + timedelta(minutes=61))
    assert stored_groups(db)[0].status == "CLOSED"
    assert stored_groups(db)[0].closed_at is not None

    actions = [e.action for e in stored_group_audit(db)]
    assert "GROUP_QUIET" in actions
    assert "GROUP_CLOSED" in actions


def test_quiet_group_reactivates_on_new_member(db):
    """4.29: new in-window member while QUIET -> QUIET -> ACTIVE."""
    from tests.aggregation.helpers import fabricate_alerts

    alerts = fabricate_alerts(db, [dict(minutes_ago=10.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    group.status = "QUIET"
    db.commit()

    new = fabricate_alerts(db, [dict(detector_id="D002", mitre="T1110", minutes_ago=2.0)])
    process_alerts(db, new, now=GROUP_T0)
    group = stored_groups(db)[0]
    assert group.status == "ACTIVE"
    assert group.alert_count == 2
    assert "GROUP_REACTIVATED" in [e.action for e in stored_group_audit(db)]


def test_closed_group_never_absorbs_new_alerts(db):
    """BG closed at 11:10; 12:30 activity -> NEW group (4.16)."""
    alerts = make_alerts(db, [dict(minutes_ago=70.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)  # ACTIVE->QUIET then QUIET->CLOSED
    assert stored_groups(db)[0].status == "CLOSED"

    later = make_alerts(db, [dict(detector_id="D002", mitre="T1110", minutes_ago=30.0)])
    process_alerts(db, later, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 2
    assert groups[0].alert_count == 1
    assert groups[1].alert_count == 1
    assert groups[1].status == "ACTIVE"

    actions = [e.action for e in stored_group_audit(db)]
    assert "GROUP_REOPEN_REJECTED" in actions


def test_new_matching_alert_while_active_attaches(db):
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    more = make_alerts(db, [dict(detector_id="D002", mitre="T1110", minutes_ago=0.0)])
    process_alerts(db, more, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 2
    assert "ALERT_ADDED" in [e.action for e in stored_group_audit(db)]


def test_audit_events_have_group_id_action_actor_details(db):
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    events = stored_group_audit(db)
    assert events[0].action == "GROUP_CREATED"
    assert events[0].behavior_group_id.startswith("BG-")
    assert events[0].actor == "system"
    assert isinstance(events[0].details, dict)