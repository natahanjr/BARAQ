"""Rule - Data from Network Shared Drive (MITRE T1039, Collection).

Detect bulk reads from network shares via dir, type, or other utilities
accessing UNC paths, indicating collection from shared drives.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_NETWORK_ACCESS_PATTERNS = [
    "dir \\\\",
    "dir \\\\\\\\",
    "dir //",
    "type \\\\",
    "type \\\\\\\\",
    "more \\\\",
    "more \\\\\\\\",
    "cat \\\\",
    "cat \\\\\\\\",
    "get-childitem \\\\",
    "get-childitem \\\\\\\\",
    "ls \\\\",
    "ls \\\\\\\\",
    "net use \\\\",
    "net use \\\\\\\\",
    "net share",
    "wmic /node:",
    "powershell.*get-smbshare",
    "powershell.*get-smbconnection",
    "powershell.*get-fileshare",
    "powershell.*invoke-command.*\\\\",
]


class NetworkShareCollectionRule(BaseRule):
    rule_id = "T1039"
    name = "Data from Network Shared Drive"
    description = (
        "Network share access or bulk read activity detected via UNC path "
        "interactions, suggesting collection from shared network drives."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1039"
    recommendation = (
        "Determine if the share access is authorized, review the volume of "
        "data accessed, check for signs of data exfiltration, and audit "
        "share-level permissions."
    )

    def __init__(self, session: Session, org: str | None = None):
        super().__init__(session, org)

    def evaluate(
        self, window_minutes: int, since_id: int | None = None
    ) -> list[DetectionResult]:
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        stmt = (
            select(NormalizedEvent)
            .where(
                NormalizedEvent.event_id.in_([4688, 4104]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
            .order_by(NormalizedEvent.timestamp.desc())
        )

        findings: list[DetectionResult] = []
        seen: set[int] = set()

        for ev in self.session.scalars(stmt).all():
            if ev.id in seen:
                continue

            facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
            cmdline = (
                facts.get("command_line")
                or facts.get("cmdline")
                or ""
            )
            if not cmdline:
                continue

            cmdline_lower = cmdline.lower()
            matched_patterns = [
                pat
                for pat in _NETWORK_ACCESS_PATTERNS
                if pat.lower() in cmdline_lower
            ]
            if not matched_patterns:
                continue

            seen.add(ev.id)
            evidence = (
                f"Network share collection detected: matched [{', '.join(matched_patterns)}] "
                f"in command line '{cmdline}' by user '{ev.user}' on host "
                f"'{ev.host or 'unknown'}' at {ev.timestamp.isoformat()}."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[ev.id],
                )
            )

        return findings
