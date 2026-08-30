"""Rule - Windows event log clearing (MITRE T1070.001).

Flags Security log clears (Event 1102), System log clears (Event 104) and
deletion of .evtx event-log files (Sysmon Event 23) - evidence that an
adversary tried to erase traces.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_LOG_CLEAR_EVENTS = (1102, 104)


class LogClearingRule(BaseRule):
    rule_id = "log_clearing"
    name = "Windows Event Log Clearing"
    description = (
        "Security/System event logs were cleared or event-log (.evtx) files "
        "were deleted - an adversary attempting to erase forensic traces."
    )
    severity = "critical"
    confidence = 0.9
    mitre_id = "T1070.001"
    recommendation = (
        "Treat the host as compromised, restore logs from central collection "
        "(SIEM) or WER/backup, and review the account that performed the clearing."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([*_LOG_CLEAR_EVENTS, 23]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for event in rows:
            if event.event_id in _LOG_CLEAR_EVENTS:
                label = "Security" if event.event_id == 1102 else "System"
                findings.append(
                    self._result(
                        evidence=f"The {label} event log was cleared by '{event.user}'.",
                        event_ids=[event.id],
                    )
                )
                continue

            # Sysmon Event 23 - file deleted
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            path = facts.get("file_path") or ""
            if not path.lower().endswith(".evtx"):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Event log file deleted: '{path}' by '{event.user}'. "
                        f"Indicates log tampering."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings
