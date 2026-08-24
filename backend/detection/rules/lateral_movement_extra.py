"""Rule set - Lateral Movement techniques (TA0008).

Covers RDP hijacking (T1021.001), SMB admin-share access (T1021.002),
WinRM (T1021.006) and SSH (T1021.004) based movement, plus remote
desktop session abuse.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NetworkConnection, NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_SMB_SHARE = re.compile(
    r"\b(?:net\s+use|copy|robocopy|xcopy)\b[^\n]*\\\\[^\\\n]+\\\$(?:c|admin|ipc)|\b(?:net\s+use)\b",
    re.IGNORECASE,
)
_WINRM = re.compile(
    r"\bwinrs(?:\.exe)?\b|\b(?:Invoke-Command|Enter-PSSession|New-PSSession)\b[^\n]*(?<!\w)-ComputerName\b",
    re.IGNORECASE,
)
_SSH = re.compile(
    r"\bssh(?:\.exe)?\b[^\n]*(?<!\w)(?:-T|-t)\b[^\n]*\b(?:cmd|powershell|bash|sh)\b|"
    r"\bplink(?:\.exe)?\b",
    re.IGNORECASE,
)
_RDP_HIJACK = re.compile(
    r"\btscon\b[^\n]*\b/dest:\b|\b(?:mstsc|query\s+session)\b",
    re.IGNORECASE,
)

#: RDP logon type 10 = remote interactive (RDP session).
_RDP_PORTS = {3389}


class SmbAdminShareRule(BaseRule):
    rule_id = "smb_admin_share"
    name = "SMB Admin Share Access"
    description = (
        "An administrative share (C$, ADMIN$, IPC$) was mounted or copied "
        "to/from - the canonical Windows lateral-movement primitive."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1021.002"
    recommendation = (
        "Identify the source host and account, disable administrative "
        "shares where possible, and review executed files on the target."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SMB_SHARE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Admin share access by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        # Network-level: outbound connections to SMB (445) on other hosts.
        rows = self.session.scalars(
            select(NetworkConnection).where(
                NetworkConnection.observed_at >= since,
                NetworkConnection.remote_port == 445,
                NetworkConnection.state == "ESTABLISHED",
                *self._org_conds(NetworkConnection),
            )
        ).all()
        if rows:
            findings.append(
                self._result(
                    evidence=(
                        f"{len(rows)} established SMB connections to remote hosts "
                        f"({sorted({r.remote_ip for r in rows})[:5]}) - possible "
                        f"admin share lateral movement."
                    ),
                    event_ids=[],
                    severity="medium",
                    confidence=0.6,
                )
            )
        return findings


class RdpLateralRule(BaseRule):
    rule_id = "rdp_lateral"
    name = "RDP Remote Interactive Logon"
    description = (
        "A remote-interactive (logon type 10) session was established - "
        "RDP is the most abused lateral-movement channel."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1021.001"
    recommendation = (
        "Validate the session against known change windows, restrict RDP "
        "to authorized users/hosts, and enable NLA and session recording."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 4624,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            logon_type = facts.get("logon_type")
            if int(logon_type or 0) != 10:
                continue
            src = facts.get("source_ip", "?")
            findings.append(
                self._result(
                    evidence=(
                        f"Remote interactive logon (type 10) for '{event.user}' "
                        f"from {src} on host '{event.host}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class WinRmLateralRule(BaseRule):
    rule_id = "winrm_lateral"
    name = "WinRM Remote Execution"
    description = (
        "WinRM or PowerShell Remoting was used against a remote host - an "
        "increasingly common lateral-movement channel."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1021.006"
    recommendation = (
        "Verify the session against approved automation, restrict WinRM "
        "listeners to management subnets, and enable session transcripts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _WINRM.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"WinRM / PS-Remoting use by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        rows = self.session.scalars(
            select(NetworkConnection).where(
                NetworkConnection.observed_at >= since,
                NetworkConnection.remote_port.in_([5985, 5986]),
                NetworkConnection.state == "ESTABLISHED",
                *self._org_conds(NetworkConnection),
            )
        ).all()
        if rows:
            findings.append(
                self._result(
                    evidence=(
                        f"{len(rows)} WinRM connections to "
                        f"{sorted({r.remote_ip for r in rows})[:5]} - possible "
                        f"remote administration."
                    ),
                    event_ids=[],
                    severity="medium",
                    confidence=0.55,
                )
            )
        return findings


class SshLateralRule(BaseRule):
    rule_id = "ssh_lateral"
    name = "SSH Remote Command Execution"
    description = (
        "SSH was used to run a command or interactive shell on a remote "
        "host - lateral movement via the SSH channel."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1021.004"
    recommendation = (
        "Validate the SSH session, require key-based auth, and review "
        "command execution logs on the target host."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SSH.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"SSH remote execution by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings