"""Rule set - Privilege Escalation techniques (TA0004).

Covers UAC bypasses (T1548.002), SeDebugPrivilege abuse (T1134.001),
named-pipe impersonation (T1134.005), unquoted service paths (T1574.009),
and AlwaysInstallElevated (T1574.005).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_SUSPICIOUS_DIRS = re.compile(
    r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\", re.IGNORECASE
)

_UAC_BYPASS = re.compile(
    r"\b(?:fodhelper|computerdefaults|eventvwr|sdclt|slui)\.exe\b[^\n]*"
    r"(?:ms-settings|msc$|/v\b|shell:::|registry)|"
    r"\breg(?:\.exe)?\s+add\b[^\n]*\\App\s+Paths\b",
    re.IGNORECASE,
)
_SE_DEBUG = re.compile(
    r"\bSeDebugPrivilege\b|"
    r"\bwhoami\b[^\n]*\b/priv\b[^\n]*\bSeDebugPrivilege\b|"
    r"\bAdjustTokenPrivileges\b|"
    r"\bEnableDebugPrivilege\b",
    re.IGNORECASE,
)
_PIPE_IMPERSONATION = re.compile(
    r"\b(?:CreateNamedPipe|ConnectNamedPipe|ImpersonateNamedPipeClient)\b|"
    r"\\\\.\\pipe[\\\\/]?(?:lsass|spoolss|srvsvc|msf|meterpreter)\b",
    re.IGNORECASE,
)
_UNQUOTED_PATH = re.compile(
    r"(?<!\")[A-Za-z]:\\[^\"\n]*\s[^\"\n]*\.exe(?!\")",
    re.IGNORECASE,
)
_ALWAYS_INSTALL = re.compile(
    r"\bAlwaysInstallElevated\b[^\n]*0x1|"
    r"\bAlwaysInstallElevated\b[^\n]*\bREG_DWORD\b[^\n]*\b1\b",
    re.IGNORECASE,
)


class UacBypassRule(BaseRule):
    rule_id = "uac_bypass"
    name = "UAC Bypass Attempt"
    description = (
        "An auto-elevating binary (fodhelper, computerdefaults, eventvwr, "
        "sdclt) was invoked with arguments used to bypass User Account "
        "Control and gain elevated execution."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1548.002"
    recommendation = (
        "Terminate the elevated process, review the registry keys it wrote, "
        "and harden UAC to 'Always Notify' with protected admin mode."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _UAC_BYPASS.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"UAC bypass attempt by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class SeDebugPrivilegeRule(BaseRule):
    rule_id = "se_debug_privilege"
    name = "SeDebugPrivilege Enable / Abuse"
    description = (
        "SeDebugPrivilege is the most dangerous Windows privilege: "
        "whoami/AdjustTokenPrivileges output or calls enabling it precede "
        "process and LSASS manipulation."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1134.001"
    recommendation = (
        "Restrict SeDebugPrivilege to Administrators, review the processes "
        "started after the call, and inspect any LSASS access that follows."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SE_DEBUG.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"SeDebugPrivilege manipulation by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class NamedPipeImpersonationRule(BaseRule):
    rule_id = "named_pipe_impersonation"
    name = "Named Pipe Impersonation"
    description = (
        "A process created or impersonated a named pipe that mirrors "
        "privileged services - a token-impersonation escalation technique "
        "used by tools like Impacket and meterpreter."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1134.005"
    recommendation = (
        "Identify the process holding the pipe, terminate it, review its "
        "token acquisition, and monitor for subsequent privileged actions."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _PIPE_IMPERSONATION.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Named-pipe impersonation by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class UnquotedServicePathRule(BaseRule):
    rule_id = "unquoted_service_path"
    name = "Unquoted Service Path"
    description = (
        "A service was installed with an unquoted image path containing "
        "spaces - exploitable via DLL planting in the writable intermediate "
        "directories (T1574.009)."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1574.009"
    recommendation = (
        "Quote the service ImagePath, remove write permissions from the "
        "intermediate directories, and scan them for planted executables."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 7045,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            path = facts.get("image_path") or facts.get("service_file") or ""
            if not _UNQUOTED_PATH.search(path):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Service '{facts.get('service_name', '?')}' installed with "
                        f"unquoted path '{path}' as '{event.user}' (Event {event.event_id})."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class AlwaysInstallElevatedRule(BaseRule):
    rule_id = "always_install_elevated"
    name = "AlwaysInstallElevated Enabled"
    description = (
        "AlwaysInstallElevated registry values permit MSI packages to run "
        "with SYSTEM privileges - a classic privilege escalation vector."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1574.005"
    recommendation = (
        "Remove the AlwaysInstallElevated values from both HKLM and HKCU, "
        "and audit MSI installations for elevation abuse."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 13,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = facts.get("target_object") or ""
            if "AlwaysInstallElevated" not in target:
                continue
            details = facts.get("details") or ""
            findings.append(
                self._result(
                    evidence=(
                        f"AlwaysInstallElevated = '{details}' at '{target}' by "
                        f"'{facts.get('image', '?')}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings
