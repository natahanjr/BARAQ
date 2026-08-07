"""Tests for the alert workflow state machine and per-rule throttling."""
from __future__ import annotations

import pytest

from backend.database.models import Alert
from backend.detection.alerting import AlertingService
from backend.detection.rules.base import DetectionResult
from backend.detection.workflow import TRANSITIONS, can_transition, next_states


def _result(rule: str, name: str, severity: str = "high", evidence: str = "") -> DetectionResult:
    return DetectionResult(
        rule=rule,
        name=name,
        description="test",
        severity=severity,
        confidence=0.8,
        evidence=evidence,
        event_ids=[],
        mitre_id="T0000",
    )


def test_workflow_transition_table_consistent():
    for state, reachable in TRANSITIONS.items():
        for target in reachable:
            assert can_transition(state, target), f"{state}->{target} missing"
        # reflexive
        assert can_transition(state, state)
        assert target in next_states(state) or state in next_states(state)
    # representative legal / illegal pairs
    assert can_transition("open", "acknowledged")
    assert can_transition("acknowledged", "investigating")
    assert can_transition("investigating", "resolved")
    assert can_transition("resolved", "closed")
    assert can_transition("closed", "open")  # reopen
    assert not can_transition("closed", "investigating")
    assert not can_transition("open", "bogus")


def test_alerting_throttle_caps_alerts_per_rule(db):
    service = AlertingService(db)
    # 6 findings of the same rule within the same window
    for i in range(6):
        service.handle_findings(
            [_result("brute_force", f"Brute Force #{i}", evidence=f"User 'admin' attempt {i}")]
        )
    alerts = db.query(Alert).all()
    # The 6th finding should refresh instead of opening a new alert.
    assert len(alerts) == 5
    assert all(a.status == "open" for a in alerts)
    refreshed = max(alerts, key=lambda a: a.updated_at)
    assert refreshed.trigger_count > 1


def test_throttle_does_not_merge_different_rules(db):
    service = AlertingService(db)
    service.handle_findings(
        [_result("brute_force", "BF", evidence="User 'admin' x1")]
    )
    service.handle_findings([_result("brute_force", "BF", evidence="User 'admin' x2")])
    service.handle_findings([_result("network_recon", "Recon", evidence="User 'alice' scan")])
    rules = {a.rule for a in db.query(Alert).all()}
    assert rules == {"brute_force", "network_recon"}


def test_acknowledged_alert_refreshes_not_duplicates(db):
    service = AlertingService(db)
    service.handle_findings([_result("brute_force", "BF", evidence="User 'admin' hit")])
    alert = db.query(Alert).one()
    alert.status = "acknowledged"
    db.commit()
    service.handle_findings([_result("brute_force", "BF", evidence="User 'admin' hit again")])
    assert db.query(Alert).count() == 1  # refreshed, not duplicated
    assert db.query(Alert).one().status == "acknowledged"


def test_dev_harness_evidence_is_not_persisted(db):
    """Test-harness commands (e.g. exercising rules from a shell) must never
    produce real alerts, even when the strings they use look malicious."""
    from backend.detection.alerting import _is_dev_harness

    assert _is_dev_harness(
        "Artifact-hiding activity by 'HAARAPHEL\\Haaraphel' (pid 7260 "
        "(powershell.exe)): ADS reference '\\evil.exe:payload'. Command line: "
        "powershell.exe -c \"from backend.detection.rules.hidden_artifacts "
        "import _ADS; tests = [...]\""
    )
    assert not _is_dev_harness(
        "Artifact-hiding activity by 'haaked' (pid 9001 (cmd.exe)): "
        "ADS reference 'C:\\Windows\\Temp\\payload.exe:stream'. "
        "Command line: C:\\Windows\\Temp\\payload.exe"
    )

    service = AlertingService(db)
    service.handle_findings(
        [
            _result(
                "hidden_artifacts",
                "Artifact Hiding Activity",
                severity="high",
                evidence=(
                    "Artifact-hiding activity by 'HAARAPHEL\\Haaraphel' "
                    "(pid 7260 (powershell.exe)): ADS reference '\\evil.exe:payload'. "
                    "Command line: powershell.exe -c \"from "
                    "backend.detection.rules.hidden_artifacts import _ADS\""
                ),
            )
        ]
    )
    assert db.query(Alert).count() == 0

    service.handle_findings(
        [
            _result(
                "hidden_artifacts",
                "Artifact Hiding Activity",
                severity="high",
                evidence=(
                    "Artifact-hiding activity by 'haaked' (pid 9001 (cmd.exe)): "
                    "ADS reference 'C:\\Windows\\Temp\\payload.exe:stream'"
                ),
            )
        ]
    )
    assert db.query(Alert).count() == 1
    assert db.query(Alert).one().evidence.startswith("Artifact-hiding activity by 'haaked'")