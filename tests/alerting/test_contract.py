"""Alert contract tests (Phase 3, spec 3.3-3.4)."""
from __future__ import annotations

import pytest

from backend.alerting.contract import (
    ALERT,
    ALERT_SEVERITIES,
    ALERT_STATUSES,
    FEEDBACK_TYPES,
)


def test_alert_has_all_required_fields():
    alert = ALERT(
        alert_id="ALR-000001",
        detection_id="D001-abc",
        detection_ids=("D001-abc",),
        alert_fingerprint="fp123",
        title="External Remote RDP Logon",
        description="desc",
        severity="high",
        confidence=0.91,
        status="OPEN",
        first_seen=None,
        last_seen=None,
        occurrence_count=1,
        host_id="",
        host_name="ml-host",
        user_id="",
        username="ml-online-user",
        source_ip="185.0.0.1",
        destination_ip="",
        mitre_tactic="Initial Access",
        mitre_technique="T1133",
        evidence=({"field": "logon_type", "value": 10, "reason": "Remote Interactive Logon"},),
        observables=(),
        detector_id="D001",
        detector_version="1.0.0",
    )
    data = alert.to_dict()
    for key in (
        "alert_id", "detection_id", "detection_ids", "alert_fingerprint", "title",
        "description", "severity", "confidence", "status", "first_seen", "last_seen",
        "occurrence_count", "host_id", "host_name", "user_id", "username",
        "source_ip", "destination_ip", "mitre_tactic", "mitre_technique",
        "evidence", "observables", "detector_id", "detector_version",
        "created_at", "updated_at", "assigned_to", "acknowledged_at",
        "resolved_at", "feedback",
    ):
        assert key in data, f"missing contract field {key}"


def test_severity_values():
    assert ALERT_SEVERITIES == ("low", "medium", "high", "critical")


def test_status_values():
    assert set(ALERT_STATUSES) == {
        "OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "RESOLVED", "CLOSED", "SUPPRESSED",
    }


def test_feedback_values():
    assert set(FEEDBACK_TYPES) == {
        "TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN", "DUPLICATE",
        "EXPECTED_ACTIVITY", "UNKNOWN",
    }


def test_alert_retains_detection_reference():
    alert = ALERT(
        alert_id="ALR-000001",
        detection_id="D001-abc",
        detection_ids=("D001-abc", "D001-def"),
        alert_fingerprint="fp123",
        title="t", severity="high", confidence=0.9, status="OPEN",
    )
    assert alert.detection_id == "D001-abc"
    assert alert.detection_ids == ("D001-abc", "D001-def")


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        ALERT(alert_id="ALR-1", detection_id="d", alert_fingerprint="f",
              title="t", severity="urgent", confidence=0.5, status="OPEN")