"""Rule - Credential Access via LSASS memory dumping (MITRE T1003.001).

Flags Sysmon Event 10 (Process Access) operations that open a handle on
lsass.exe from a process outside the small set that legitimately queries
it (Windows services and AV agents).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_LSASS = re.compile(r"lsass\.exe$", re.IGNORECASE)

# Processes that routinely hold handles to lsass.exe.
BENIGN_SOURCES = (
    "svchost.exe", "wininit.exe", "winlogon.exe", "services.exe",
    "csrss.exe", "lsass.exe", "msmpeng.exe", "taskmgr.exe", "sihost.exe",
    "dllhost.exe", "fontdrvhost.exe", "conhost.exe",
)


class CredentialAccessRule(BaseRule):
    rule_id = "credential_access"
    name = "LSASS Memory Access"
    description = (
        "A process opened a handle to LSASS with memory-access permissions - "
        "a classic precursor to credential dumping (Mimikatz sekurlsa, etc.)."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1003.001"
    recommendation = (
        "Kill the offending process, rotate all local and cached credentials, "
        "enable Credential Guard, and inspect logons made with the stolen hashes."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 10,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = (facts.get("target_image") or "").lower()
            if not _LSASS.search(target):
                continue

            source = (facts.get("image") or "").lower()
            source_bin = source.rsplit("\\", 1)[-1] if "\\" in source else source
            if source_bin in BENIGN_SOURCES:
                continue

            granted = facts.get("granted_access") or "0x0"
            findings.append(
                self._result(
                    evidence=(
                        f"Process '{source_bin or facts.get('image', '?')}' opened a handle "
                        f"on {target} (access mask {granted}) as '{event.user}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings