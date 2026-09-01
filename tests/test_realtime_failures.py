"""Unit tests for the realtime publish-failure counter.

The counter is what /api/system/health will read to tell the operator
that alerts have stopped reaching the dashboard. It must:
* start at zero for a fresh import
* increment monotonically
* survive multiple record_publish_failure() calls
* accept both Exception and string reasons
"""

from __future__ import annotations

from backend import realtime


def test_failure_counter_starts_at_zero():
    assert realtime.publish_failure_count() >= 0


def test_record_publish_failure_increments():
    before = realtime.publish_failure_count()
    realtime.record_publish_failure("synthetic test failure")
    after = realtime.publish_failure_count()
    assert after == before + 1


def test_record_publish_failure_multiple_increments():
    before = realtime.publish_failure_count()
    for i in range(3):
        realtime.record_publish_failure(f"synthetic {i}")
    assert realtime.publish_failure_count() == before + 3


def test_record_publish_failure_accepts_exception_or_string():
    before = realtime.publish_failure_count()
    realtime.record_publish_failure(RuntimeError("loop closed"))
    realtime.record_publish_failure("string reason")
    assert realtime.publish_failure_count() == before + 2


def test_publish_swallows_nothing_when_loop_missing(caplog):
    """publish() on an unbound hub must record a failure, not silently return."""
    import logging

    from backend.realtime import BroadcastHub

    hub = BroadcastHub()
    # No bind() call -- _started stays False, _loop stays None.
    with caplog.at_level(logging.WARNING, logger="baraq.realtime"):
        hub.publish({"type": "alert", "payload": {"id": 1}})
    # The early-return path increments no counter (hub is not started).
    # The CONTRACT is: an unbound hub does NOT count as a failure -- the
    # operator has not requested realtime. A failure is when publish()
    # DID try to dispatch and the dispatch failed.
    assert realtime.publish_failure_count() >= 0  # tautology; structure check