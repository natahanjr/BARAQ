"""Rule 5 - Network Reconnaissance (MITRE T1046, Discovery).

Detects port-scanning behaviour: a single source probing many distinct
remote ports of one host within a short window.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import NetworkConnection
from backend.detection.rules.base import BaseRule, DetectionResult

SCAN_STATES = {"SYN_SENT", "CLOSE_WAIT", "TIME_WAIT"}


class NetworkReconRule(BaseRule):
    rule_id = "network_recon"
    name = "Network Service Discovery (Port Scan)"
    description = (
        "A source address probed many distinct ports on a remote host within "
        "a short window, characteristic of network reconnaissance."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1046"
    recommendation = (
        "Block the scanning source at the firewall, inspect the initiating "
        "process and hunt for follow-on exploitation activity."
    )

    def __init__(self, session, distinct_ports: int = 20, window_seconds: int = 120):
        super().__init__(session)
        self.distinct_ports = distinct_ports
        self.window_seconds = window_seconds

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)
        findings: list[DetectionResult] = []

        stmt = (
            select(
                NetworkConnection.local_ip,
                NetworkConnection.remote_ip,
                func.count(func.distinct(NetworkConnection.remote_port)).label("ports"),
                func.count(NetworkConnection.id).label("attempts"),
                func.min(NetworkConnection.observed_at).label("first_ts"),
                func.max(NetworkConnection.observed_at).label("last_ts"),
            )
            .where(
                NetworkConnection.observed_at >= since,
                *self._org_conds(NetworkConnection),
            )
            .group_by(NetworkConnection.local_ip, NetworkConnection.remote_ip)
            .having(func.count(func.distinct(NetworkConnection.remote_port)) >= self.distinct_ports)
        )

        for row in self.session.execute(stmt).all():
            if row.local_ip in ("", "::1", "127.0.0.1"):
                continue
            evidence = (
                f"{row.attempts} connection attempts from {row.local_ip} to "
                f"{row.remote_ip} across {row.ports} distinct ports within "
                f"{self.window_seconds} seconds."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="high" if row.ports >= self.distinct_ports * 2 else "medium",
                    confidence=min(0.95, 0.6 + row.ports * 0.005),
                )
            )
        return findings
