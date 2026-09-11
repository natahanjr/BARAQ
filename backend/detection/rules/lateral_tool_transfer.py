"""Rule - Lateral Tool Transfer (MITRE T1570, Lateral Movement).

Detect file copies to remote SMB shares via copy, xcopy, robocopy, or
PsExec-style file drops to UNC paths.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_COPY_TOOLS = [
    "copy \\\\",
    "copy \\\\\\\\",

    "xcopy \\\\",
    "xcopy \\\\\\\\",

    "robocopy \\\\",
    "robocopy \\\\\\\\",

    "powershell.*copy-item \\\\",
    "powershell.*copy-item \\\\\\\\",
    "powershell.*copy \\\\",

    "smbclient",
    "psexec",
    "psexec",
    "mimikatz",
    "certutil.*-urlcache",
]


class LateralToolTransferRule(BaseRule):
    rule_id = "T1570"
    name = "Lateral Tool Transfer"
    description = (
        "File transfer to a remote SMB/UNC share detected, indicating potential "
        "lateral tool transfer between systems."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1570"
    recommendation = (
        "Identify the source and destination hosts, validate the transfer is "
        "authorized, inspect transferred files for malware, and review SMB "
        "share permissions."
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
            matched_tools = [
                tool for tool in _COPY_TOOLS if tool.lower() in cmdline_lower
            ]
            if not matched_tools:
                continue

            seen.add(ev.id)
            evidence = (
                f"Lateral tool transfer detected: matched [{', '.join(matched_tools)}] "
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
