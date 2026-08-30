"""Engine unit tests (Phase 2)."""

from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.engine import run_detection, run_detections
from backend.detection.registry import Registry
from tests.detection.helpers import event, logon_failed, logon_success


def test_run_detection_pure_no_side_effects(db):
    """Evaluating events changes nothing: no alerts, no incidents, no risk."""
    from sqlalchemy import text

    tables = ("alerts", "incidents", "entity_risk")
    before = {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in tables
    }
    events = [
        logon_success(1, logon_type=10, source_ip="203.0.113.5"),
        logon_failed(2),
    ]
    findings = run_detections(events, DetectionContext(db))
    assert any(f.detector_id == "D001" for f in findings)
    after = {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in tables
    }
    assert after == before
    assert db.execute(text('SELECT COUNT(*) FROM "detections"')).scalar() == 0


def test_run_detection_deterministic():
    events = [
        logon_success(1, logon_type=10, source_ip="203.0.113.5"),
        logon_failed(2),
    ]
    first = [(f.detection_id, f.title) for f in run_detections(events)]
    second = [(f.detection_id, f.title) for f in run_detections(events)]
    assert first == second


def test_run_detection_swallows_detector_errors():
    class BrokenDetector:
        id = "ZZZ"
        version = "0.0.1"
        name = "broken"
        description = ""
        enabled = True
        supported_event_types = ()

        def supports(self, event):
            return True

        def evaluate(self, event, context=None):
            raise RuntimeError("boom")

    registry = Registry()
    registry.register(BrokenDetector())
    from backend.detection.detectors.d001_external_rdp import ExternalRDPDetector

    registry.register(ExternalRDPDetector())
    events = [logon_success(1, logon_type=10, source_ip="203.0.113.5")]
    findings = run_detection(events[0], registry=registry)
    assert [f.detector_id for f in findings] == ["D001"]


def test_persist_refuses_production_db_name(monkeypatch, db):
    """Phase 2.5: persist must refuse the v1 production database by name."""
    import pytest

    from backend import config
    from backend.detection.contract import DETECTION
    from backend.detection.engine import persist

    monkeypatch.setattr(
        config, "DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel"
    )
    finding = DETECTION(
        detector_id="D001",
        detector_version="1.0.0",
        event_id=event().fingerprint(),
        event_ids=(event().fingerprint(),),
        timestamp=event().timestamp,
        first_seen=event().timestamp,
        last_seen=event().timestamp,
        event_type="authentication",
        host_name="workstation-42",
        username="alice",
        title="External Remote RDP Logon",
        severity="high",
        confidence=0.99,
        mitre_tactic="Initial Access",
        mitre_technique="T1133",
    )
    with pytest.raises(RuntimeError, match="production database"):
        persist(db, finding)
    from sqlalchemy import text

    assert db.execute(text('SELECT COUNT(*) FROM "detections"')).scalar() == 0
