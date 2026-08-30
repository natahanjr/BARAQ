"""Rule - Binary masquerading (MITRE T1036).

Flags processes named after trusted system binaries (svchost, lsass, csrss,
winlogon, services, ...) whose image path is NOT under C:\\Windows - the
binary is being copied and renamed to evade analysis and allow-lists.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent, ProcessRecord
from backend.detection.rules.base import BaseRule, DetectionResult

SYSTEM_BINARIES = {
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "wininit.exe",
    "lsm.exe",
    "spoolsv.exe",
    "dwm.exe",
    "taskhostw.exe",
    "conhost.exe",
    "explorer.exe",
    "dllhost.exe",
}

# Legitimate homes for these binaries; everything else is suspect.
_WINDOWS_PREFIXES = (
    r"^\w:\\windows\\",
    r"^\w:\\windows$",
    r"^c:\\windows",
)
_WINDOWS_PREFIX = re.compile("|".join(_WINDOWS_PREFIXES), re.IGNORECASE)


def _is_system_path(path: str) -> bool:
    return bool(_WINDOWS_PREFIX.match((path or "").lower()))


class MasqueradingRule(BaseRule):
    rule_id = "masquerading"
    name = "Masquerading System Binary"
    description = (
        "A process named after a trusted Windows binary is executing from a "
        "path outside C:\\Windows - consistent with copy-and-rename evasion."
    )
    severity = "high"
    confidence = 0.85
    mitre_id = "T1036"
    recommendation = (
        "Terminate the masquerading process, delete the binary, scan the "
        "originating directory and review the parent process chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(ProcessRecord).where(
                ProcessRecord.observed_at >= since,
                *self._org_conds(ProcessRecord),
                ProcessRecord.name.isnot(None),
                ProcessRecord.name != "",
            )
        ).all()

        for pr in rows:
            name = (pr.name or "").lower()
            if name not in SYSTEM_BINARIES:
                continue
            if _is_system_path(pr.path or ""):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"'{pr.name}' (called '{name}') is executing from "
                        f"'{pr.path}' as '{pr.user or '?'}' (pid {pr.pid})."
                    ),
                    event_ids=[],
                )
            )

        # Security-eventlog (4688) process creations carry the same signal as
        # ProcessRecord snapshots, so the rule also covers eventlog-only
        # deployments where no process snapshot collector is installed.
        for ev in self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 4688,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all():
            facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
            image_path = str(facts.get("image_path") or ev.message or "").strip()
            if not image_path:
                continue
            name = image_path.rsplit("\\", 1)[-1].lower()
            if name not in SYSTEM_BINARIES:
                continue
            if _is_system_path(image_path):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"'{name}' (called '{name}') is executing from "
                        f"'{image_path}' as '{ev.user or '?'}' (Event {ev.event_id})."
                    ),
                    event_ids=[ev.id],
                )
            )
        return findings
