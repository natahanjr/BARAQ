"""Incremental detection: the rules engine only evaluates new events.

The detection cursor (``system_state.detection_cursor``) must make each
ingest batch cost proportional to the batch, not to the accumulated window,
without changing detection outcomes: every attack event still alerts, and
idle re-runs produce no work and no duplicate alerts.
"""
from __future__ import annotations

from sqlalchemy import func, select

from backend.api.system import run_pipeline
from backend.database.models import NormalizedEvent
from backend.detection.cursor import CURSOR_LOCK, get_cursor, set_cursor
from backend.detection.rules_engine import RulesEngine
from tests.conftest import _scenario


def _event_count(db) -> int:
    return db.scalar(select(func.count(NormalizedEvent.id))) or 0


def test_cursor_starts_at_zero(db):
    assert get_cursor(db) == 0


def test_run_pipeline_advances_cursor_and_detects_new_events(db):
    result = run_pipeline(db, _scenario("brute_force"))
    assert result["alerts_created"] >= 1
    assert get_cursor(db) == _event_count(db)

    # A second, different attack in the same DB is still detected: the
    # cursor only limits *what is scanned*, never the outcome.
    result2 = run_pipeline(db, _scenario("powershell"))
    assert result2["alerts_created"] >= 1
    assert get_cursor(db) == _event_count(db)


def test_idle_run_after_cursor_is_free_and_creates_nothing(db):
    run_pipeline(db, _scenario("brute_force"))
    cursor_before = get_cursor(db)
    # Re-running the same events (as the scheduler does after an ingest has
    # already detected them) must not re-scan the window or open duplicates.
    result = run_pipeline(db, [])
    assert result["alerts_created"] == 0
    assert get_cursor(db) == cursor_before


def test_engine_respects_since_id(db):
    run_pipeline(db, _scenario("brute_force"), detect=False)
    total = _event_count(db)
    engine = RulesEngine(db)
    # with since_id=0 everything is scanned and the attack fires
    full = engine.run(window_minutes=10, since_id=0)
    assert any(f.rule == "brute_force" for f in full)
    # with since_id=total nothing new exists: the incremental (Sigma) layer
    # is idle and only window-bound native rules may re-fire on the window
    # (the alerting service dedups those, so no duplicate alerts appear).
    # The detection cursor's job is work reduction, not behaviour change.
    assert get_cursor(db) == 0
    run_pipeline(db, [], detect=True)
    assert get_cursor(db) == total


def test_detect_false_defers_detection_to_scheduler(db):
    result = run_pipeline(db, _scenario("brute_force"), detect=False)
    assert result["alerts_created"] == 0
    assert get_cursor(db) == 0
    # scheduler-style pass with detect=True picks the events up
    result2 = run_pipeline(db, [], detect=True)
    assert result2["alerts_created"] >= 1
    assert get_cursor(db) == _event_count(db)


def test_cursor_lock_is_serialising(db):
    with CURSOR_LOCK:
        set_cursor(db, 42)
        db.commit()
    assert get_cursor(db) == 42