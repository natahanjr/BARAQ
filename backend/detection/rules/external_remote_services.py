"""Rule - External Remote Services (MITRE T1133, Initial Access).

Detect anomalous logons from external/public IPs via RDP (EventID 4624
LogonType 10), VPN, or SSH.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

# RFC 1918 + loopback + link-local prefixes to exclude
_INTERNAL_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.", "169.254.",
    "::1", "fe80:",
)

_REMOTE_LOGON_TYPES = {10}  # RemoteInteractive (RDP)


def _is_external_ip(ip: str | None) -> bool:
    if not ip:
        return False
    ip_lower = ip.lower().strip()
    if ip_lower in ("", "-", "::1", "127.0.0.1", "localhost"):
        return False
    return not any(ip_lower.startswith(pfx) for pfx in _INTERNAL_PREFIXES)


class ExternalRemoteServicesRule(BaseRule):
    rule_id = "T1133"
    name = "External Remote Services"
    description = (
        "Detected interactive logon (RDP type 10) from an external/public IP "
        "address, suggesting use of external remote services for initial access."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1133"
    recommendation = (
        "Verify the legitimacy of the external connection, restrict RDP to "
        "VPN or jump-host access, enforce NLA, and review firewall rules."
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
                NormalizedEvent.event_id == 4624,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
            .order_by(NormalizedEvent.timestamp.desc())
        )

        findings: list[DetectionResult] = []
        for ev in self.session.scalars(stmt).all():
            facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
            logon_type = facts.get("logon_type") or facts.get("LogonType")
            source_ip = (
                facts.get("source_ip")
                or facts.get("IpAddress")
                or facts.get("ip_address")
                or ""
            )

            try:
                logon_type = int(logon_type)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue

            if logon_type not in _REMOTE_LOGON_TYPES:
                continue

            if not _is_external_ip(str(source_ip)):
                continue

            evidence = (
                f"External interactive logon (type {logon_type}) detected from "
                f"IP {source_ip} for account '{ev.user}' on host "
                f"'{ev.host or 'unknown'}' at {ev.timestamp.isoformat()}."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[ev.id],
                )
            )

        return findings
