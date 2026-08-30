"""Regression tests for the scrub_docs.ps1 false-positive wave (Aug 2026).

The platform raised ~23 HIGH alerts for opencode's own helper script
``powershell -NoProfile -ExecutionPolicy Bypass -File ...\\Temp\\opencode\\scrub_docs.ps1``
because of three stacked defects:

1. ``hidden_execution`` counted bare ``-NoProfile`` as malicious;
2. the BARAQ Sigma encoded-command rule matched the substring ``-e``;
3. alert dedup never merged repeats (case-sensitive user extraction) and
   the reopen-guard's inner-loop ``continue`` never suppressed re-triggers.

Each test pins one layer so none can silently regress.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from backend.database.models import Alert, NormalizedEvent
from backend.detection.alerting import AlertingService, _alert_user
from backend.detection.fp_filters import is_trusted_agent_activity
from backend.detection.rules.powershell import (
    SUSPICIOUS_PATTERNS,
    SuspiciousPowerShellRule,
)

SCRUB_DOCS_CMD = (
    "C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    " -NoProfile -ExecutionPolicy Bypass -File"
    " C:\\Users\\HAARAP~1\\AppData\\Local\\Temp\\opencode\\scrub_docs.ps1"
)


def _add_event(db, command_line: str, user: str = "-") -> None:
    db.add(
        NormalizedEvent(
            source="test",
            event_id=4688,
            category="process",
            severity="info",
            message=command_line[:200],
            user=user,
            host="haaraphel",
            timestamp=datetime.now(UTC),
            raw_json={"facts": {"command_line": command_line}},
        )
    )
    db.commit()


# ---------------------------------------------------------------------------
# Layer 1 - rule precision + trusted-agent FP filter
# ---------------------------------------------------------------------------


def test_bare_noprofile_is_not_hidden_execution():
    assert SUSPICIOUS_PATTERNS["hidden_execution"].search(SCRUB_DOCS_CMD) is None


def test_real_hidden_window_still_matches():
    assert SUSPICIOUS_PATTERNS["hidden_execution"].search(
        "powershell -w hidden -File x.ps1"
    )
    assert SUSPICIOUS_PATTERNS["hidden_execution"].search(
        "powershell -WindowStyle Hidden"
    )


@pytest.mark.parametrize(
    "text",
    [
        SCRUB_DOCS_CMD,
        r"AppData\Local\Temp\opencode\shoot.py",
    ],
)
def test_trusted_agent_paths_filtered(text):
    assert is_trusted_agent_activity(text)


def test_attack_tools_not_filtered():
    assert not is_trusted_agent_activity(
        "powershell -EncodedCommand SQBFAFgA -w hidden"
    )


def test_scrubdocs_never_alerts_native_rule(db):
    _add_event(db, SCRUB_DOCS_CMD)
    assert SuspiciousPowerShellRule(db).evaluate(10) == []


def test_genuine_hidden_temp_script_still_alerts(db):
    _add_event(db, "powershell.exe -w hidden -File C:\\Users\\pub\\Temp\\x.ps1")
    findings = SuspiciousPowerShellRule(db).evaluate(10)
    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Layer 2 - dedup signature matching
# ---------------------------------------------------------------------------


def test_evidence_user_extraction_case_insensitive():
    evidence = "PowerShell script block (Event 4688) from user '-' matched 1 indicators"
    assert _alert_user(evidence) == "-"


class _Result:
    """Minimal DetectionResult stand-in."""

    def __init__(
        self, name="Suspicious PowerShell Activity", rule="suspicious_powershell"
    ):
        self.name = name
        self.rule = rule
        self.description = "d"
        self.severity = "high"
        self.confidence = 0.8
        self.mitre_id = "T1059.001"
        self.recommendation = ""
        self.correlation_id = ""
        self.evidence = "PowerShell script block (Event 4688) from user '-' matched 1 indicators: hidden_execution."
        self.event_ids = []


def test_unknown_user_repeats_merge_into_one_alert(db):
    svc = AlertingService(db)
    first = svc.handle_findings([_Result()], org="")
    second = svc.handle_findings([_Result()], org="")
    third = svc.handle_findings([_Result()], org="")
    assert len(first) == 1
    assert second == [] and third == [], "repeats merge, nothing new created"
    alerts = db.scalars(
        select(Alert).where(Alert.rule == "suspicious_powershell")
    ).all()
    assert len(alerts) == 1, "repeats must refresh one alert, not spawn new ones"
    assert alerts[0].trigger_count == 3


def test_reopen_guard_absorbs_closed_alert_repeat(db):
    """Regression: guard previously bumped counters then created a NEW alert anyway."""
    svc = AlertingService(db)
    svc.handle_findings([_Result()], org="")
    alert = db.scalars(select(Alert).where(Alert.rule == "suspicious_powershell")).one()
    alert.status = "closed"
    alert.updated_at = datetime.now(UTC)
    db.commit()

    created = svc.handle_findings([_Result()], org="")

    assert created == []
    alerts = db.scalars(
        select(Alert).where(Alert.rule == "suspicious_powershell")
    ).all()
    assert len(alerts) == 1 and alerts[0].status == "closed"
