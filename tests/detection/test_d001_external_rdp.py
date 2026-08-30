"""Detector D001 - External RDP Logon tests (Phase 2)."""

from __future__ import annotations

from backend.detection.engine import run_detection
from tests.detection.helpers import event, logon_failed, logon_success


def d001(event):
    findings = [f for f in run_detection(event) if f.detector_id == "D001"]
    return findings[0] if findings else None


# positive ----------------------------------------------------------------------


def test_external_rdp_logon_type_10_detected():
    detection = d001(logon_success(1, logon_type=10, source_ip="203.0.113.5"))
    assert detection is not None
    assert detection.detector_id == "D001"
    assert detection.severity == "high"
    assert 0.0 <= detection.confidence <= 1.0
    assert detection.mitre_technique == "T1133"
    assert detection.source_ip == "203.0.113.5"


def test_evidence_fields_explain_why():
    detection = d001(logon_success(1, logon_type=10, source_ip="203.0.113.5"))
    fields = [e.field for e in detection.evidence]
    assert "logon_type" in fields
    assert "source_ip" in fields
    assert all(e.reason not in ("", "Rule matched") for e in detection.evidence)


# negative ----------------------------------------------------------------------


def test_logon_type_2_private_ip_not_detected():
    assert d001(logon_success(1, logon_type=2, source_ip="10.0.0.5")) is None


def test_logon_type_10_private_ip_not_detected():
    assert d001(logon_success(1, logon_type=10, source_ip="192.168.1.50")) is None


def test_non_logon_action_not_detected():
    assert d001(logon_failed(1, source_ip="203.0.113.5")) is None


def test_logon_type_missing_not_detected():
    assert d001(logon_success(1, source_ip="203.0.113.5")) is None


# boundary ----------------------------------------------------------------------


def test_logon_type_non_numeric_not_detected():
    detection = d001(
        event(
            action="logon",
            event_type="authentication",
            network={"src_ip": "203.0.113.5"},
            facts={"logon_type": "rdp-via-tunnel"},
        )
    )
    assert detection is None


def test_confidence_deterministic_and_in_range():
    a = d001(logon_success(1, logon_type=10, source_ip="8.8.8.8", user="alice"))
    b = d001(logon_success(1, logon_type=10, source_ip="8.8.8.8", user="alice"))
    assert a.confidence == b.confidence
    assert 0.0 <= a.confidence <= 1.0


# missing field / duplicate / multiple event -------------------------------------


def test_missing_source_ip_not_detected():
    detection = d001(
        event(
            action="logon",
            event_type="authentication",
            network={},
            facts={"logon_type": 10},
        )
    )
    assert detection is None


def test_duplicate_event_identical_detection_id():
    e1 = logon_success(1, logon_type=10, source_ip="203.0.113.5")
    e2 = logon_success(1, logon_type=10, source_ip="203.0.113.5")
    assert e1.fingerprint() == e2.fingerprint()
    assert d001(e1).detection_id == d001(e2).detection_id


def test_single_event_never_creates_multiple_detections():
    findings = run_detection(logon_success(1, logon_type=10, source_ip="203.0.113.5"))
    assert len([f for f in findings if f.detector_id == "D001"]) == 1
