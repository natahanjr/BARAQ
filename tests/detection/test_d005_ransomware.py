"""Detector D005 - Ransomware behavior tests (Phase 2)."""
from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.engine import run_detection
from backend.detection.registry import default_registry

from tests.detection.helpers import file_modify, seed_events, shadow_delete


def evaluate(db, current, seeded):
    if seeded:
        seed_events(db, seeded)
    context = DetectionContext(db)
    findings = [f for f in run_detection(current, context) if f.detector_id == "D005"]
    return findings[0] if findings else None


# positive ----------------------------------------------------------------------


def test_20_file_mods_detected(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is not None
    assert detection.severity == "medium"
    assert detection.mitre_technique == "T1486"
    assert detection.host_name == "workstation-42"


def test_50_plus_file_mods_high_severity(db):
    seeded = [file_modify(i * 0.05) for i in range(1, 60)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is not None
    assert detection.severity == "high"


def test_shadow_delete_escalates_severity(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    seeded += [shadow_delete(2)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is not None
    assert detection.severity == "high"


def test_shadow_delete_strengthens_confidence(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    plain = evaluate(db, file_modify(0), seeded)
    seeded += [shadow_delete(2)]
    with_shadow = evaluate(db, file_modify(0), seeded)
    assert with_shadow.confidence > plain.confidence
    assert any(e.field == "shadow_copy_deletion" for e in with_shadow.evidence)


def test_60_plus_file_mods_higher_confidence(db):
    """60 mods (3x threshold) raises confidence; 50 is not a crossing."""
    seeded = [file_modify(i * 0.05) for i in range(1, 60)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is not None
    assert detection.confidence > 0.70


# negative ----------------------------------------------------------------------


def test_single_file_event_not_detected(db):
    assert evaluate(db, file_modify(0), []) is None


def test_19_file_mods_not_detected(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 19)]
    assert evaluate(db, file_modify(0), seeded) is None


def test_mods_other_host_not_counted(db):
    seeded = [file_modify(i * 0.2, host="server-01") for i in range(1, 20)]
    assert evaluate(db, file_modify(0), seeded) is None


def test_shadow_delete_alone_not_detected(db):
    assert evaluate(db, shadow_delete(0), []) is None


# boundary ----------------------------------------------------------------------


def test_exactly_20_detected(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is not None


def test_mods_outside_5_min_window_not_counted(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 19)]
    seeded += [file_modify(i + 30) for i in range(6)]
    detection = evaluate(db, file_modify(0), seeded)
    assert detection is None  # 18 in window + 1 current = 19 < 20


def test_confidence_bounded(db):
    seeded = [file_modify(i * 0.05) for i in range(1, 60)]
    detection = evaluate(db, file_modify(0), seeded)
    assert 0.0 <= detection.confidence <= 1.0


# missing field / duplicate / multiple event -------------------------------------


def test_missing_process_name_still_detected(db):
    current = file_modify(0)
    current = current.__class__(
        timestamp=current.timestamp, host=current.host, user=current.user,
        source=current.source, action=current.action, facts=current.facts,
        event_type=current.event_type, process={},
    )
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    detection = evaluate(db, current, seeded)
    assert detection is not None


def test_duplicate_batch_no_extra_detections(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    seed_events(db, seeded)
    seed_events(db, seeded)
    context = DetectionContext(db)
    findings = [f for f in run_detection(file_modify(0), context) if f.detector_id == "D005"]
    assert len(findings) == 1


def test_windowed_detection_carries_all_event_ids(db):
    seeded = [file_modify(i * 0.2) for i in range(1, 20)]
    detection = evaluate(db, file_modify(0), seeded)
    assert len(detection.event_ids) == 20