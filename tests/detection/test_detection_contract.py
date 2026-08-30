"""Detection contract unit tests (Phase 2)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from backend.detection.contract import DETECTION, make_detection_id
from backend.detection.evidence import Evidence, classify_ip, ev, is_external


def make_event(**overrides):
    from backend.telemetry.contract import EVENT

    base = {
        "timestamp": datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC),
        "host": "workstation-42",
        "user": "alice",
        "source": "windows-security",
        "action": "logon",
        "facts": {"logon_type": 10},
    }
    base.update(overrides)
    return EVENT(**base)


def make_detection(**overrides):
    event = make_event()
    base = {
        "detector_id": "D001",
        "detector_version": "1.0.0",
        "event_id": event.fingerprint(),
        "event_ids": (event.fingerprint(),),
        "timestamp": event.timestamp,
        "first_seen": event.timestamp,
        "last_seen": event.timestamp,
        "event_type": event.event_type,
        "host_name": event.host,
        "username": event.user,
        "source_ip": "203.0.113.5",
        "title": "External Remote RDP Logon",
        "severity": "high",
        "confidence": 0.9,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1133",
        "evidence": (ev("logon_type", 10, "Remote Interactive Logon"),),
    }
    base.update(overrides)
    return DETECTION(**base)


# --- validation ---------------------------------------------------------------


def test_rejects_invalid_severity():
    with pytest.raises(ValueError):
        make_detection(severity="urgent")


def test_rejects_invalid_status():
    with pytest.raises(ValueError):
        make_detection(status="resolved")


def test_clamps_confidence_out_of_range():
    detection = make_detection(confidence=1.7)
    assert detection.confidence == 1.0
    detection = make_detection(confidence=-0.2)
    assert detection.confidence == 0.0


def test_rounds_confidence_to_3_decimals():
    detection = make_detection(confidence=0.12345)
    assert detection.confidence == 0.123


def test_detection_id_is_deterministic():
    d1 = make_detection()
    d2 = make_detection()
    assert d1.detection_id == d2.detection_id
    assert d1.detection_id.startswith("D001-")
    assert len(d1.detection_id) == 5 + 12


def test_detection_id_changes_with_event():
    other = make_event(timestamp=datetime(2026, 8, 17, 13, 0, 0, tzinfo=UTC))
    d = make_detection(event_id=other.fingerprint())
    assert d.detection_id != make_detection().detection_id


# --- serialization -------------------------------------------------------------


def test_to_dict_roundtrip_shape():
    detection = make_detection()
    data = detection.to_dict()
    assert data["detector_id"] == "D001"
    assert data["detection_id"] == detection.detection_id
    assert data["severity"] == "high"
    assert data["confidence"] == 0.9
    assert data["evidence"][0]["field"] == "logon_type"
    assert data["event_ids"] == [detection.event_id]


def test_to_explain_contains_evidence():
    text = make_detection().to_explain()
    assert "Why detected" in text
    assert "logon_type" in text
    assert "T1133" in text


# --- evidence -------------------------------------------------------------------


def test_evidence_requires_reason():
    evidence = ev("host", "x", "reason here")
    assert isinstance(evidence, Evidence)
    assert evidence.reason == "reason here"


# --- IP classification ----------------------------------------------------------


def test_classify_ip_categories():
    assert classify_ip("10.1.2.3") == "private"
    assert classify_ip("192.168.0.1") == "private"
    assert classify_ip("172.16.0.1") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.1.1") == "link_local"
    assert classify_ip("224.0.0.1") == "reserved"
    assert classify_ip("203.0.113.5") == "external"
    assert classify_ip("8.8.8.8") == "external"


def test_is_external_only_public():
    assert is_external("203.0.113.5")
    assert not is_external("10.0.0.1")
    assert not is_external("192.168.1.5")


def test_make_detection_id_helper():
    assert make_detection_id("D002", "a", "b") == make_detection_id("D002", "a", "b")
    assert make_detection_id("D002", "a", "b") != make_detection_id("D002", "a", "c")
