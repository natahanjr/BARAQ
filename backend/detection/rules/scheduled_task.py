"""Rule - Scheduled Task persistence abuse (MITRE T1053.005).

Detects schtasks /create (or /change) invocations where the task name
masquerades as a system component, the action binary lives in a
user-writable directory, or the task is triggered at logon/startup.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_CREATE = re.compile(
    r"\bschtasks(?:\.exe)?\s+(?:/create|/change|-create|-change)\b", re.IGNORECASE
)
_MASQUERADE = re.compile(
    r"(windowsupdate|windowsupdater|systemupdate|systemmaintenance|adobeupdate|"
    r"googleupdate|microsoftupdate|windowsdefender|windowssecurity)",
    re.IGNORECASE,
)
_SUSPICIOUS_DIRS = re.compile(
    r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\|\\ProgramData\\",
    re.IGNORECASE,
)
_STARTUP_TRIGGER = re.compile(
    r"/sc\b[^\s]*?\b(onlogon|onstart|onboot|onidle)", re.IGNORECASE
)


class ScheduledTaskAbuseRule(BaseRule):
    rule_id = "scheduled_task_abuse"
    name = "Suspicious Scheduled Task Creation"
    description = (
        "schtasks.exe was used to create or change a scheduled task with "
        "system-masquerading names, user-writable action paths or "
        "logon/startup triggers - a common persistence pattern."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1053.005"
    recommendation = (
        "Delete the task, remove the dropped binary, disable remote task "
        "creation where possible, and audit all scheduled tasks on the host."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not _CREATE.search(cmdline):
                continue

            indicators = []
            if _MASQUERADE.search(cmdline):
                indicators.append("task name masquerades as a system component")
            if _SUSPICIOUS_DIRS.search(cmdline):
                indicators.append("action binary in user-writable directory")
            if _STARTUP_TRIGGER.search(cmdline):
                indicators.append("logon/startup trigger")
            if not indicators:
                continue

            findings.append(
                self._result(
                    evidence=(
                        f"Scheduled task created/changed by '{user}' ({label}): "
                        f"{'; '.join(indicators)}. Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
