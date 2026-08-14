"""Rule set - Discovery techniques (TA0007).

Covers account discovery (T1087), network share discovery (T1135),
system information discovery (T1082), domain enumeration (T1482),
security software discovery (T1518.001) and file/registry discovery
(T1083).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from backend.detection.rules.base import BaseRule, DetectionResult

_ACCOUNT_DISCOVERY = re.compile(
    r"\bnet\s+user\b|\bnet\s+localgroup\b|\bnet\s+group\b|\bwhoami\b|\bquery\s+user\b|"
    r"\b(?:Get-LocalUser|Get-ADUser|Get-WmiObject\s+-Class\s+Win32_UserAccount|dsquery\s+user)\b|"
    r"\bnet\s+accounts\b",
    re.IGNORECASE,
)
_SHARE_DISCOVERY = re.compile(
    r"\bnet\s+view\b|\bnet\s+share\b|\b(?:Get-SmbShare|Get-ChildItem)\b[^\n]*\\\\|"
    r"\bdir\s+\\\\|\\bnet\s+use\b",
    re.IGNORECASE,
)
_SYSINFO = re.compile(
    r"\bsysteminfo\b|\bhostname\b|\bver\b(?!\s*=)|"
    r"\bipconfig\s+/all\b|"
    r"\b(?:Get-ComputerInfo|Get-WmiObject\s+-Class\s+Win32_ComputerSystem)\b",
    re.IGNORECASE,
)
_DOMAIN_DISCOVERY = re.compile(
    r"\bnltest\s+/dclist\b|\bnltest\s+/dsgetdc\b|\bnet\s+dom\b|\bdsquery\b|"
    r"\b(?:Get-ADDomain|Get-ADForest|Get-ADDomainController|nltest\s+/trusted_domains)\b|"
    r"\bnet\s+group\s+/domain\b",
    re.IGNORECASE,
)
_SECURITY_SOFTWARE = re.compile(
    r"\bwmic\b[^\n]*\bAntivirusProduct\b|\bwmic\b[^\n]*\bSecurityCenter2\b|"
    r"\bGet-MpComputerStatus\b|\bsc\s+query\b[^\n]*\b(?:WinDefend|MpsSvc|Sense)\b|"
    r"\b(?:Get-Process|tasklist)\b[^\n]*\b(?:MsMpEng|Sense|wscsvc)\b",
    re.IGNORECASE,
)
_FILESYSTEM = re.compile(
    r"\bdir\s+[A-Za-z]:\\|\b(?:Get-ChildItem|ls)\b[^\n]*(?<!\w)(?:-Recurse|-Force)\b",
    re.IGNORECASE,
)


class AccountDiscoveryRule(BaseRule):
    rule_id = "account_discovery"
    name = "Account Enumeration"
    description = (
        "User and group enumeration commands were executed - identifying "
        "accounts and privilege structure for follow-on attacks."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1087"
    recommendation = (
        "Review the parent process chain, restrict enumeration tooling "
        "where possible, and monitor for credential attacks against "
        "enumerated accounts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _ACCOUNT_DISCOVERY.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Account enumeration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ShareDiscoveryRule(BaseRule):
    rule_id = "share_discovery"
    name = "Network Share Enumeration"
    description = (
        "Network shares were enumerated with net view/share or SMB "
        "queries - mapping file shares for lateral movement."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1135"
    recommendation = (
        "Audit share permissions, disable unnecessary admin shares, and "
        "monitor for access to enumerated share paths."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SHARE_DISCOVERY.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Share enumeration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class SystemInfoDiscoveryRule(BaseRule):
    rule_id = "system_info_discovery"
    name = "System Information Gathering"
    description = (
        "System configuration was collected (systeminfo, hostname, "
        "ipconfig /all) - profiling the host for later exploitation."
    )
    severity = "low"
    confidence = 0.55
    mitre_id = "T1082"
    recommendation = (
        "Review the parent process chain; single invocations are common in "
        "troubleshooting, but repeated breadth of discovery commands "
        "suggests reconnaissance."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SYSINFO.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"System information gathering by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class DomainDiscoveryRule(BaseRule):
    rule_id = "domain_discovery"
    name = "Domain Trust / Structure Enumeration"
    description = (
        "Active Directory domain controllers, forests and trust "
        "relationships were enumerated - mapping the domain for "
        "targeted attacks."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1482"
    recommendation = (
        "Review the enumerating account and host, restrict nltest/dsquery "
        "access where possible, and watch for credential attacks against "
        "discovered domain controllers."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _DOMAIN_DISCOVERY.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Domain enumeration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class SecuritySoftwareDiscoveryRule(BaseRule):
    rule_id = "security_software_discovery"
    name = "Security Product Discovery"
    description = (
        "Installed security products were enumerated (AV status, firewall "
        "service state) - scouting for defenses to bypass."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1518.001"
    recommendation = (
        "Review the querying process, watch for follow-on attempts to "
        "disable the discovered products, and monitor AV service state "
        "changes."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SECURITY_SOFTWARE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Security product discovery by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class FileSystemDiscoveryRule(BaseRule):
    rule_id = "filesystem_discovery"
    name = "File System Reconnaissance"
    description = (
        "Recursive directory listings were performed - searching for "
        "sensitive files (credentials, documents, configs) to collect."
    )
    severity = "low"
    confidence = 0.55
    mitre_id = "T1083"
    recommendation = (
        "Review the searched paths and initiating process; combined with "
        "staging activity this indicates active data collection."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _FILESYSTEM.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Recursive file listing by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings