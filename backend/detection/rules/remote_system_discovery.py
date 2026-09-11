"""Rule - Remote System Discovery (MITRE T1018, Discovery).

Detect use of built-in and third-party discovery tools such as net view,
nltest, dsquery, arp, and ping sweep utilities.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_DISCOVERY_TOOLS = [
    "net view",
    "nltest",
    "dsquery",
    "dsget",
    "arp ",
    "arp\t",
    "nbtstat",
    "net view \\\\",
    "net group \"domain computers\"",
    "net group \"domain controllers\"",
    "net localgroup \"domain admins\"",
    "ping -n",
    "powershell.*test-netconnection",
    "powershell.*get-adcomputer",
    "powershell.*get-aduser",
    "powershell.*get-addomain",
    "powershell.*get-adforest",
    "powershell.*get-wmiobject",
    "powershell.*get-ciminstance",
    "powershell.*resolve-dnsname",
    "systeminfo",
    "ipconfig /all",
    "netstat -an",
    "tasklist",
    "qwinsta",
    "wmic.*qfe",
]


class RemoteSystemDiscoveryRule(BaseRule):
    rule_id = "T1018"
    name = "Remote System Discovery"
    description = (
        "Discovery tool execution detected via process creation events with "
        "command lines containing known system/network enumeration utilities."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1018"
    recommendation = (
        "Investigate the account and host performing discovery, determine if "
        "the activity is authorized, and review for follow-on lateral movement."
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
                or facts.get("NewProcessName")
                or ""
            )
            if not cmdline:
                continue

            cmdline_lower = cmdline.lower()
            matched_tools = [
                tool for tool in _DISCOVERY_TOOLS if tool.lower() in cmdline_lower
            ]
            if not matched_tools:
                continue

            seen.add(ev.id)
            evidence = (
                f"Discovery tool usage detected: matched [{', '.join(matched_tools)}] "
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
