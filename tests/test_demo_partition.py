"""Session-level demo partition: production detection must never see demo rows.

Detection (``run_detection``), the scheduler cycle and demo seeding set
``session.info["baraq_demo"]`` (True = demo/test data, False = production)
around their work; the ``do_orm_execute`` hook in
``backend.database.connection`` then restricts every SELECT on demo-aware
tables to the matching partition. These tests lock in the behaviour that:

* demo telemetry (including child tables such as process snapshots) can
  never be re-detected as production alerts,
* demo alerting/RBA state never merges into production state,
* the outer partition flag survives nested detection runs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from backend.api.system import run_detection, run_pipeline
from backend.database.models import Alert, ProcessRecord
from backend.risk.entity_risk import EntityRiskManager

PYTHON_ALERT = "Python Execution from User-Writable Path"


def _process(db, command_line: str, demo: bool) -> None:
    db.add(
        ProcessRecord(
            pid=14932,
            ppid=1,
            name="python.exe",
            path="C:\\Users\\t\\AppData\\Local\\Temp\\python.exe",
            command_line=command_line,
            parent_name="",
            user="alice",
            is_new=False,
            observed_at=datetime.now(UTC),
            org="",
            demo=demo,
        )
    )
    db.commit()


def _python_record(command_line: str) -> dict:
    return {
        "source": "process",
        "pid": 14932,
        "ppid": 1,
        "name": "python.exe",
        "path": "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe",
        "raw": {"cmdline": command_line},
        "user": "alice",
        "timestamp": datetime.now(UTC).isoformat(),
    }


def test_selects_are_scoped_to_the_active_partition(db):
    _process(db, "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe demo.py", demo=True)
    _process(db, "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe prod.py", demo=False)

    assert db.query(ProcessRecord).count() == 2  # no flag -> everything

    db.info["baraq_demo"] = True
    try:
        assert db.query(ProcessRecord).count() == 1
        assert len(db.scalars(select(ProcessRecord)).all()) == 1
    finally:
        db.info.pop("baraq_demo", None)

    db.info["baraq_demo"] = False
    try:
        assert db.query(ProcessRecord).count() == 1
        assert len(db.scalars(select(ProcessRecord)).all()) == 1
    finally:
        db.info.pop("baraq_demo", None)


def test_demo_process_records_never_alert_in_production(db):
    # The exact regression from the analyst audit: a demo process snapshot
    # (python from a user-writable path) was re-detected by the production
    # scheduler as a real alert.
    _process(
        db,
        "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe script.py",
        demo=True,
    )

    _, created = run_detection(db, org="", window_minutes=10, demo=False)
    assert created == []

    _, created = run_detection(db, org="", window_minutes=10, demo=True)
    assert len(created) == 1
    assert created[0].name == PYTHON_ALERT
    assert created[0].demo is True


def test_production_and_demo_detection_do_not_merge(db):
    _process(db, "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe a.py", demo=True)
    _process(db, "C:\\Users\\t\\AppData\\Local\\Temp\\python.exe b.py", demo=False)

    _, created = run_detection(db, org="", window_minutes=10, demo=False)
    assert len(created) == 1
    assert created[0].name == PYTHON_ALERT
    assert created[0].demo is False

    # The demo pass sees the demo snapshot only - the production alert from
    # the previous pass must not be deduped/merged into the demo one.
    _, created = run_detection(db, org="", window_minutes=10, demo=True)
    assert len(created) == 1
    assert created[0].demo is True

    assert db.query(Alert).count() == 2
    assert {a.demo for a in db.query(Alert).all()} == {True, False}


def test_escalate_production_run_ignores_demo_entities(db):
    from tests.test_entity_risk import _mk_alert

    alert = _mk_alert(
        db, host="WS-DEMO", risk_score=90.0, evidence="User 'demo' from 10.9.9.9"
    )
    alert.demo = True
    db.commit()
    EntityRiskManager(db).apply_alert(alert)
    db.commit()

    db.info["baraq_demo"] = False
    try:
        assert EntityRiskManager(db).escalate(org="") == []
    finally:
        db.info.pop("baraq_demo", None)

    db.info["baraq_demo"] = True
    try:
        created = EntityRiskManager(db).escalate(org="")
    finally:
        db.info.pop("baraq_demo", None)
    # host + user + ip entities from the alert evidence
    assert len(created) == 3
    assert all(a.name.startswith("Entity Risk Escalation:") for a in created)
    assert all(a.demo is True for a in created)


def test_detection_restores_outer_partition_flag(db):
    db.info["baraq_demo"] = True
    try:
        _, created = run_detection(db, org="", window_minutes=10, demo=False)
        assert created == []
        # The outer (scheduler-cycle) partition survives the nested run.
        assert db.info["baraq_demo"] is True
    finally:
        db.info.pop("baraq_demo", None)


def test_pipeline_tags_child_records_with_demo(db):
    run_pipeline(
        db,
        [_python_record("C:\\Users\\t\\AppData\\Local\\Temp\\python.exe -c x")],
        org="",
        detect=False,
        demo=True,
    )
    rows = db.query(ProcessRecord).all()
    assert rows
    assert all(r.demo is True for r in rows)
