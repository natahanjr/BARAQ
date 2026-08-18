"""Alert audit trail tests (spec 3.27, 3.35)."""
from __future__ import annotations

from backend.alerting import audit
from backend.alerting.engine import process_detection
from backend.alerting.models import AlertRecord

from tests.alerting.helpers import detection, stored_audit


def _alert(db) -> AlertRecord:
    return process_detection(db, detection())


def test_created_event_on_creation(db):
    _alert(db)
    events = stored_audit(db)
    assert len(events) == 1
    assert events[0].action == "CREATED"
    assert events[0].previous_status == ""
    assert events[0].new_status == "OPEN"
    assert events[0].actor == "system"
    assert events[0].details["detection_id"]


def test_occurrence_event_on_merge(db):
    _alert(db)
    process_detection(db, detection(minutes_ago=0.1))
    events = stored_audit(db)
    assert [e.action for e in events] == ["CREATED", "OCCURRENCE"]
    assert events[1].actor == "system"


def test_actor_recorded(db):
    process_detection(db, detection(), actor="analyst@example")
    assert stored_audit(db)[0].actor == "analyst@example"


def test_manual_audit_records(db):
    audit.record(
        db,
        alert_id="ALR-000001",
        action="ASSIGNED",
        previous_status="OPEN",
        new_status="OPEN",
        actor="analyst@example",
        details={"assigned_to": "analyst@example"},
    )
    db.commit()
    events = stored_audit(db)
    assert events[0].action == "ASSIGNED"
    assert events[0].details == {"assigned_to": "analyst@example"}


def test_for_alert_scoped(db):
    a = _alert(db)
    process_detection(db, detection(minutes_ago=0.1))
    events = audit.for_alert(db, a.alert_id)
    assert len(events) == 2
    assert all(e.alert_id == a.alert_id for e in events)


def test_suppressed_detection_is_audited(db):
    from datetime import timedelta

    from backend.alerting.suppression import create_rule

    from tests.alerting.helpers import T0

    create_rule(db, policy_id="SUP-1", reason="approved maintenance",
                expires_at=T0 + timedelta(hours=1),
                scope={"detector_id": "D001", "host": "workstation-42"})
    db.commit()
    process_detection(db, detection())
    events = stored_audit(db)
    assert events[0].action == "SUPPRESSED"
    assert events[0].details["policy_id"] == "SUP-1"