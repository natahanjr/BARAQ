"""Rule - BITS Jobs (MITRE T1197).

Adversaries abuse Windows BITS (Background Intelligent Transfer Service) to
stage/download/execute payloads while evading autostart and network defences.
This rule flags the key abuse surface: bitsadmin /transfer (and job-creation
with a notification command line), Start-BitsTransfer, and BITS transfers that
land in user-writable or temp directories.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_BITS_TRANSFER = re.compile(
    r"\bbitsadmin(?:\.exe)?\s+/transfer\b|"
    r"\bbitsadmin(?:\.exe)?\s+/create\b[^\n]*?(?:/addfile|/SetNotifyCmdLine)\b|"
    r"\bStart-BitsTransfer\b",
    re.IGNORECASE,
)

_SUSPICIOUS_TARGET = re.compile(
    r"[/\\](?:users\\public|windows\\temp|temp|appdata|programdata|downloads?)[/\\]",
    re.IGNORECASE,
)

_NOTIFY = re.compile(r"/SetNotifyCmdLine\b", re.IGNORECASE)


class BitsJobRule(BaseRule):
    rule_id = "bits_job"
    name = "BITS Job Abuse"
    description = (
        "A BITS transfer or notification job was created targeting a "
        "user-writable or temp directory - a common way to stage or execute "
        "malicious payloads while bypassing download monitoring (T1197)."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1197"
    recommendation = (
        "Enumerate BITS jobs (bitsadmin /list), delete the abusive job, block "
        "the download source, and inspect any payload that was transferred."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _BITS_TRANSFER.search(cmdline):
                continue
            indicators = []
            if _SUSPICIOUS_TARGET.search(cmdline):
                indicators.append("payload staged in user-writable/temp directory")
            if _NOTIFY.search(cmdline):
                indicators.append("job notification runs a command")
            if not indicators:
                indicators = ["BITS transfer/download activity"]
            findings.append(
                self._result(
                    evidence=(
                        f"BITS job abuse by '{user}' ({label}): "
                        f"{'; '.join(indicators)}. Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
