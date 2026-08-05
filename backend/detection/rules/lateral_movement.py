"""Rule 6 - Lateral Movement (MITRE T1021, Lateral Movement).

Detects lateral movement attempts via:
- Remote service execution (SMB/RPC connections to administrative shares)
- Multiple failed logons from internal IPs to different targets
- Administrative privilege usage across multiple hosts
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import NormalizedEvent, NetworkConnection
from backend.detection.rules.base import BaseRule, DetectionResult


class LateralMovementRule(BaseRule):
    rule_id = "lateral_movement"
    name = "Lateral Movement Detection"
    description = (
        "Detects suspicious lateral movement patterns including admin share access, "
        "multiple failed logons across different targets, and privilege usage from "
        "multiple internal hosts within a short time window."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1021"
    recommendation = (
        "Isolate affected hosts, review network segmentation, audit account privileges, "
        "and hunt for persistence mechanisms or data exfiltration."
    )

    def __init__(
        self,
        session,
        admin_share_threshold: int = 3,
        failed_logon_targets: int = 3,
        window_minutes: int = 10,
    ):
        super().__init__(session)
        self.admin_share_threshold = admin_share_threshold
        self.failed_logon_targets = failed_logon_targets
        self.window_minutes = window_minutes

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        window_minutes = self.window_minutes or window_minutes
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # Pattern 1: Admin share access (SMB port 445 to internal hosts from internal source)
        findings.extend(self._detect_admin_share_access(since))

        # Pattern 2: Multiple failed logons across different target systems
        findings.extend(self._detect_multiple_target_failed_logons(since))

        # Pattern 3: Privilege escalation across multiple hosts
        findings.extend(self._detect_privilege_elevation_spread(since))

        return findings

    def _detect_admin_share_access(self, since: datetime) -> list[DetectionResult]:
        """Detect attempts to access admin shares (port 445 - SMB)."""
        findings: list[DetectionResult] = []

        stmt = (
            select(
                NetworkConnection.local_ip,
                func.count(func.distinct(NetworkConnection.remote_ip)).label("unique_targets"),
                func.count(NetworkConnection.id).label("attempts"),
                func.min(NetworkConnection.observed_at).label("first_attempt"),
            )
            .where(
                NetworkConnection.observed_at >= since,
                NetworkConnection.remote_port == 445,
            )
            .group_by(NetworkConnection.local_ip)
            .having(func.count(func.distinct(NetworkConnection.remote_ip)) >= self.admin_share_threshold)
        )

        for row in self.session.execute(stmt).all():
            # Exclude localhost and link-local
            if row.local_ip in ("", "127.0.0.1", "::1"):
                continue

            # Check if source is internal IP (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            if not self._is_internal_ip(row.local_ip):
                continue

            evidence = (
                f"Host {row.local_ip} accessed SMB admin share (port 445) on "
                f"{row.unique_targets} distinct internal targets ({row.attempts} attempts) "
                f"starting at {row.first_attempt}. Potential lateral movement via file share access."
            )

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="high",
                    confidence=min(0.90, 0.70 + row.unique_targets * 0.05),
                )
            )

        return findings

    def _detect_multiple_target_failed_logons(self, since: datetime) -> list[DetectionResult]:
        """Detect failed logons from one account to multiple targets."""
        findings: list[DetectionResult] = []

        # Event ID 4625 = failed logon; 4624 = successful logon
        stmt = (
            select(
                NormalizedEvent.user,
                func.count(func.distinct(NormalizedEvent.host)).label("unique_targets"),
                func.count(NormalizedEvent.id).label("failed_attempts"),
                func.min(NormalizedEvent.timestamp).label("first_event"),
            )
            .where(
                NormalizedEvent.event_id == 4625,
                NormalizedEvent.timestamp >= since,
            )
            .group_by(NormalizedEvent.user)
            .having(func.count(func.distinct(NormalizedEvent.host)) >= self.failed_logon_targets)
        )

        for row in self.session.execute(stmt).all():
            if not row.user or row.user.lower() in ("system", "local service", "network service"):
                continue

            evidence = (
                f"User '{row.user}' attempted logons on {row.unique_targets} different hosts "
                f"with {row.failed_attempts} failures starting at {row.first_event}. "
                f"Pattern consistent with credential-based lateral movement."
            )

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="high" if row.failed_attempts >= 5 else "medium",
                    confidence=min(0.85, 0.65 + row.unique_targets * 0.08),
                )
            )

        return findings

    def _detect_privilege_elevation_spread(self, since: datetime) -> list[DetectionResult]:
        """Detect privilege escalation events across multiple hosts."""
        findings: list[DetectionResult] = []

        # Events 4720 (user create), 4732 (group member add), 4672 (privileged login)
        stmt = (
            select(
                NormalizedEvent.user,
                func.count(func.distinct(NormalizedEvent.host)).label("unique_hosts"),
                func.count(NormalizedEvent.id).label("escalation_events"),
                func.min(NormalizedEvent.timestamp).label("first_event"),
            )
            .where(
                NormalizedEvent.event_id.in_([4720, 4732, 4672]),
                NormalizedEvent.timestamp >= since,
            )
            .group_by(NormalizedEvent.user)
            .having(func.count(func.distinct(NormalizedEvent.host)) >= 2)
        )

        for row in self.session.execute(stmt).all():
            if not row.user or row.user.lower() in ("system", "local service"):
                continue

            evidence = (
                f"Privilege escalation activity from user '{row.user}' detected across "
                f"{row.unique_hosts} hosts ({row.escalation_events} events) starting at {row.first_event}. "
                f"Indicates potential privilege abuse and persistence mechanisms."
            )

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="critical",
                    confidence=min(0.92, 0.75 + row.unique_hosts * 0.10),
                )
            )

        return findings

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        """Check if IP is in private range."""
        if not ip:
            return False
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            first = int(parts[0])
            second = int(parts[1])
            # 10.0.0.0/8
            if first == 10:
                return True
            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            return False
        except (ValueError, IndexError):
            return False
