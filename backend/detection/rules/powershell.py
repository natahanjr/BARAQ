"""Rule 2 - Suspicious PowerShell (MITRE T1059.001, Execution).

Detects PowerShell script blocks (Event 4104) containing encoded
commands, download cradles or hidden execution flags.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.fp_filters import is_trusted_agent_activity
from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_PATTERNS = {
    "encoded_command": re.compile(r"-enc(?:odedcommand)?\b|FromBase64String", re.IGNORECASE),
    "download_cradle": re.compile(
        r"DownloadString|DownloadFile|WebClient|Invoke-WebRequest|IWR |Start-BitsTransfer",
        re.IGNORECASE,
    ),
    # Only a genuinely hidden window counts: -NoProfile / -ExecutionPolicy
    # Bypass are ubiquitous in legitimate automation and carry no signal.
    "hidden_execution": re.compile(r"-W(indowStyle)?\s+Hidden\b|-w\s+hidden\b", re.IGNORECASE),
    "reflective_invoke": re.compile(r"Invoke-Expression|iex\b|IEX\s|Invoke-Mimikatz|Get-KerberosTicket", re.IGNORECASE),
}

ADMIN_CONSOLE_PATTERNS = re.compile(
    r"New-Item|Set-ItemProperty|HKLM:|Reg Add|schtasks\s*/create|net user\s+/add",
    re.IGNORECASE,
)


class SuspiciousPowerShellRule(BaseRule):
    rule_id = "suspicious_powershell"
    name = "Suspicious PowerShell Activity"
    description = (
        "PowerShell executed with suspicious characteristics: encoded commands, "
        "download-and-execute behavior, hidden windows or reflective invocation."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1059.001"
    recommendation = (
        "Investigate the executed script block, review the parent process, "
        "isolate the host and restrict PowerShell to Constrained Language Mode."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([4104, 4103, 400, 403, 4688]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        findings: list[DetectionResult] = []
        for event in rows:
            script = event.raw_json.get("facts", {}).get("script_block", "") if event.raw_json else ""
            command_line = event.raw_json.get("facts", {}).get("command_line", "") if event.raw_json else ""
            haystack = f"{script} {command_line} {event.message}"

            # Process-creation (4688) records are only PowerShell evidence when
            # the command line actually invokes a PowerShell engine.
            if event.event_id == 4688 and not re.search(r"powershell|pwsh", haystack, re.IGNORECASE):
                continue

            # FP filter: local automation tooling running scripts from its
            # own trusted directory is expected behaviour, never an alert.
            if is_trusted_agent_activity(haystack):
                continue

            hits = [label for label, pattern in SUSPICIOUS_PATTERNS.items() if pattern.search(haystack)]
            if not hits:
                continue

            severity = self.severity
            if "encoded_command" in hits or ("download_cradle" in hits and "hidden_execution" in hits):
                severity = "critical"

            evidence = (
                f"PowerShell script block (Event {event.event_id}) from user '{event.user}' "
                f"matched {len(hits)} indicators: {', '.join(hits)}. "
                f"Snippet: {haystack[:400]}"
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[event.id],
                    severity=severity,
                    confidence=min(0.99, self.confidence + 0.04 * len(hits)),
                )
            )
        return findings
