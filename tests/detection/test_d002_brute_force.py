"""Detector D002 - Brute Force tests (Phase 2).

Deterministic window logic: evaluate the crossing failure event against a
context seeded with stored failures. Count = stored in window + current
(if not already stored).
"""
from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.engine import run_detection
from backend.detection.registry import default_registry

from tests.detection.helpers import logon_failed, logon_success, seed_events


def evaluate(db, current, seeded):
    if seeded:
        seed_events(db, seeded)
    context = DetectionContext(db)
    findings = [f for f in run_detection(current, context) if f.detector_id == "D002"]
    return findings[0] if findings else None


# positive ----------------------------------------------------------------------


def test_10_failures_within_window_detected(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 10)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection is not None
    assert detection.severity == "medium"
    assert detection.mitre_technique == "T1110"
    assert detection.username == "alice"


def test_20_failures_without_success_medium_severity(db):
    """20 failures alone is medium; high requires 30+ or 20+ with success."""
    seeded = [logon_failed(i * 0.5) for i in range(1, 20)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection is not None
    assert detection.severity == "medium"


def test_failures_outside_window_not_counted(db):
    """12 failures but 8 are older than the 15-minute window."""
    seeded = [logon_failed(i * 0.5) for i in range(1, 9)]
    seeded += [logon_failed(i + 20) for i in range(4)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection is None  # 8 in window + 1 current = 9 < 10


def test_20_failures_plus_success_escalates(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 20)]
    seeded += [logon_success(5)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection is not None
    assert detection.severity == "high"
    assert any(e.field == "successful_logon" for e in detection.evidence)


# negative ----------------------------------------------------------------------


def test_single_failure_not_detected(db):
    assert evaluate(db, logon_failed(0), []) is None


def test_5_failures_not_detected(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 5)]
    assert evaluate(db, logon_failed(0), seeded) is None


def test_9_failures_not_detected(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 9)]
    assert evaluate(db, logon_failed(0), seeded) is None


def test_successful_logon_not_detected(db):
    assert evaluate(db, logon_success(0), []) is None


def test_10_failures_different_user_not_detected(db):
    seeded = [logon_failed(i * 0.5, user="bob") for i in range(1, 10)]
    assert evaluate(db, logon_failed(0, user="alice"), seeded) is None


def test_10_failures_different_host_not_detected(db):
    seeded = [logon_failed(i * 0.5, host="server-01") for i in range(1, 10)]
    assert evaluate(db, logon_failed(0, host="workstation-42"), seeded) is None


# boundary ----------------------------------------------------------------------


def test_exactly_10_failures_detected(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 10)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection is not None
    assert detection.severity == "medium"


def test_30_failures_high(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 30)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection.severity == "high"


def test_confidence_grows_with_failures(db):
    low = evaluate(db, logon_failed(0), [logon_failed(i * 0.5) for i in range(1, 10)])
    high = evaluate(db, logon_failed(0), [logon_failed(i * 0.5) for i in range(1, 30)])
    assert high.confidence > low.confidence
    assert 0.0 <= high.confidence <= 1.0


# missing field / duplicate / multiple event -------------------------------------


def test_failure_without_username_handled(db):
    detection = evaluate(
        db,
        logon_failed(0, user="-"),
        [logon_failed(i * 0.5, user="-") for i in range(1, 10)],
    )
    assert detection is not None
    assert detection.username == "-"


def test_duplicate_batch_idempotent_detection(db):
    """Re-evaluating the same stored batch never creates a new detection."""
    seeded = [logon_failed(i * 0.5) for i in range(1, 10)]
    seed_events(db, seeded)
    seed_events(db, seeded)  # replay - no-op ingest
    context = DetectionContext(db)
    findings = [f for f in run_detection(logon_failed(0), context) if f.detector_id == "D002"]
    assert findings[0].detection_id == evaluate(db, logon_failed(0), []).detection_id


def test_windowed_detection_uses_crossing_event_id(db):
    seeded = [logon_failed(i * 0.5) for i in range(1, 10)]
    detection = evaluate(db, logon_failed(0), seeded)
    assert detection.event_id == logon_failed(0).fingerprint()