"""Rule set - Defense Evasion techniques (TA0005).

Covers disabling security products (T1562.001), firewall changes
(T1562.004), audit-policy tampering (T1562.002), registry edits used to
weaken defenses (T1112), indicator removal / log tampering (T1070) and
legitimate-signature abuse (T1553 / T1564 hidden attributes).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_SUSPICIOUS_DIRS = re.compile(r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\", re.IGNORECASE)

_DISABLE_AV = re.compile(
    r"\b(?:Stop-Service|sc(?:\.exe)?\s+stop|Set-Service\s+-Status\s+Stopped)\b[^\n]*"
    r"\b(?:WinDefend|MsMpSvc|Sense|WdBoot|WdFilter|SecurityHealthService|Defender)\b|"
    r"\bSet-MpPreference\b[^\n]*(?<!\w)(?:-DisableRealtimeMonitoring\s+\$?true|-DisableIOAVProtection\s+\$?true)|"
    r"\breg(?:\.exe)?\s+add\b[^\n]*\\Windows Defender\\\b[^\n]*\b(?:DisableAntiSpyware|DisableAntiVirus)\b",
    re.IGNORECASE,
)
_DISABLE_FIREWALL = re.compile(
    r"\bnetsh(?:\.exe)?\s+advfirewall\s+(?:set\s+allprofiles\s+state\s+off|firewall\s+set\s+opmode\s+disable)\b|"
    r"\b(?:Stop-Service|sc(?:\.exe)?\s+stop)\b[^\n]*\b(?:MpsSvc|SharedAccess)\b|"
    r"\breg(?:\.exe)?\s+add\b[^\n]*\\FirewallPolicy\\\b",
    re.IGNORECASE,
)
_DISABLE_AUDIT = re.compile(
    r"\bauditpol(?:\.exe)?\b[^\n]*(?<!\w)(?:/clear|/set\b[^\n]*\bdisable|/remove)\b|"
    r"\bwevtutil(?:\.exe)?\s+cl\b|"
    r"\bClear-EventLog\b",
    re.IGNORECASE,
)
_HIDE_ATTRIBUTES = re.compile(
    r"\battrib(?:\.exe)?\b[^\n]*\s+[+]\s*[hsr]|"
    r"\bSet-ItemProperty\b[^\n]*\b-Attributes\b[^\n]*(?:Hidden|System)\b",
    re.IGNORECASE,
)
_DISABLE_REMOTE = re.compile(
    r"\breg(?:\.exe)?\s+add\b[^\n]*\\Policies\\Microsoft\\Windows NT\\SystemRestore\b[^\n]*\bDisableSR\b|"
    r"\breg(?:\.exe)?\s+add\b[^\n]*\\Windows\b[^\n]*\\WindowsUpdate\b[^\n]*\bAU\b[^\n]*\bNoAutoUpdate\b",
    re.IGNORECASE,
)


class DisableDefenderRule(BaseRule):
    rule_id = "disable_defender"
    name = "Windows Defender Disabled / Tampered"
    description = (
        "A command stopped Windows Defender services, disabled real-time "
        "protection, or disabled the product via registry - classic "
        "defense-evasion prelude to malware execution."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1562.001"
    recommendation = (
        "Re-enable Defender services and real-time protection, verify the "
        "registry values were restored, and investigate what executed while "
        "protection was off."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _DISABLE_AV.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Defender disable/tampering by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class DisableFirewallRule(BaseRule):
    rule_id = "disable_firewall"
    name = "Windows Firewall Disabled"
    description = (
        "The Windows Firewall was turned off for all profiles or the "
        "service was stopped - removing inbound protection during an attack."
    )
    severity = "high"
    confidence = 0.85
    mitre_id = "T1562.004"
    recommendation = (
        "Re-enable the firewall for all profiles, restart the MpsSvc "
        "service, and review firewall rule changes in the last hour."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _DISABLE_FIREWALL.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Firewall disable by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class DisableAuditRule(BaseRule):
    rule_id = "disable_audit"
    name = "Audit Policy Tampering"
    description = (
        "Audit logging was cleared or disabled - erasing forensic evidence "
        "of the attacker's activity."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1562.002"
    recommendation = (
        "Re-enable audit policies, restore cleared logs from collectors, "
        "and treat this as an active-compromise indicator."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _DISABLE_AUDIT.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Audit policy tampering by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class HiddenFileAttributeRule(BaseRule):
    rule_id = "hidden_file_attribute"
    name = "Hidden / System Attribute Set"
    description = (
        "Files were marked hidden or system via attrib or PowerShell - a "
        "technique to conceal malware artifacts on disk."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1564.001"
    recommendation = (
        "List files with hidden/system attributes, inspect them with an "
        "on-demand scan, and review the initiating process."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _HIDE_ATTRIBUTES.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Hidden/system attribute set by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class DisableSystemRestoreRule(BaseRule):
    rule_id = "disable_system_restore"
    name = "System Restore / Update Disabled"
    description = (
        "Registry edits disabled System Restore or Windows Update - "
        "impairing recovery mechanisms before destructive activity."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1562.001"
    recommendation = (
        "Restore the registry values, enable System Restore and updates, "
        "and watch for follow-on destruction or encryption attempts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _DISABLE_REMOTE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"System Restore / update disabled by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings