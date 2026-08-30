"""Phase 2 regression wiring for the v1 known-problem corpus.

Each test replays the documented v1 failure pattern and asserts the v2
engine's behavior (see tests/regression/v1-known-problems/*.md):

* RDP_DUPLICATION_001       one detection per RDP logon burst (v1: 30)
* BRUTE_FORCE_OVERALERTING_001  one aggregated brute-force detection
* ransomware single event   no detection on one file modification
* side effects              v1 tables (alerts/incidents/entity_risk)
                            are never touched by detection
"""

from __future__ import annotations

from sqlalchemy import select, text

from backend.detection.context import DetectionContext
from backend.detection.engine import run_and_persist
from backend.telemetry.ingestion.pipeline import ingest
from tests.detection.helpers import (
    file_modify,
    logon_failed,
    logon_success,
    stored_events,
)

V1_TABLES = ("alerts", "incidents", "entity_risk")


def _v1_counts(db) -> dict:
    return {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar() for t in V1_TABLES
    }


def _replay(db, events) -> list:
    """Ingest canonical events, then evaluate each stored event in arrival
    order exactly as the live pipeline would; return persisted rows."""
    raw = [e.to_dict() for e in events]
    stats = ingest(db, raw)
    assert stats["failed"] == 0, f"replay failed: {stats}"
    context = DetectionContext(db)
    rows = []
    for event in stored_events(db):
        for record in run_and_persist(db, [event], context):
            rows.append(record)
    return rows


def _stored_detections(db) -> list:
    from backend.detection.models import DetectionRecord

    return list(db.scalars(select(DetectionRecord)).all())


def test_rdp_duplication_001_burst_yields_one_detection(db):
    """v1: rdp_lateral fired 1 alert per event (30 alerts for one burst)."""
    burst = [
        logon_success(i / 60, logon_type=10, source_ip="203.0.113.5") for i in range(6)
    ]
    before = _v1_counts(db)
    rows = _replay(db, burst)
    after = _v1_counts(db)

    assert len(rows) == 6  # one per event (each fire is explainable)
    stored = _stored_detections(db)
    assert len(stored) == 1  # one aggregated detection for the campaign
    assert stored[0].detector_id == "D001"
    assert stored[0].severity == "high"
    assert len(stored[0].event_ids) == 6  # campaign evidence merged
    assert after == before  # zero side effects on v1 state


def test_brute_force_overalerting_001_campaign_yields_one_detection(db):
    """v1: 15 per-event alerts + 3 alert families for one campaign."""
    failures = [logon_failed(i / 60, source_ip="198.51.100.7") for i in range(60)]
    before = _v1_counts(db)
    rows = _replay(db, failures)
    after = _v1_counts(db)

    assert len(rows) == 6  # fires at 10, 20, ..., 60
    stored = _stored_detections(db)
    assert len(stored) == 1  # one aggregated detection per account
    assert stored[0].detector_id == "D002"
    assert stored[0].severity == "high"  # 60 >= 30 escalates
    assert stored[0].confidence == 0.72  # 0.60 + 0.02 * (60 // 10)
    assert "60" in str([e for e in stored[0].evidence if e["field"] == "failed_logons"])
    assert after == before  # zero side effects on v1 state


def test_single_file_modification_no_detection(db):
    """A single file modification must never trigger D005."""
    rows = _replay(db, [file_modify(0.1)])
    assert rows == []
    assert _stored_detections(db) == []
    assert _v1_counts(db) == {"alerts": 0, "incidents": 0, "entity_risk": 0}


def test_benign_burst_no_detection_no_side_effects(db):
    """Benign traffic (internal logons + routine file edits) stays silent."""
    benign = [
        logon_success(i / 60, logon_type=2, source_ip="10.0.0.5") for i in range(5)
    ] + [file_modify(i / 60) for i in range(3)]
    before = _v1_counts(db)
    rows = _replay(db, benign)
    assert rows == []
    assert _v1_counts(db) == before
