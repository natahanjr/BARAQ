"""Rule set - Persistence techniques (TA0003).

Covers startup-folder payloads (T1547.001), registry service/image-path
persistence (T1543.003), AppInit_DLLs (T1546.010), accessibility-feature
backdoors (T1546.008), Image File Execution Options debuggers (T1546.012),
Netsh helper DLLs (T1546.007) and login scripts (T1037.001).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_SUSPICIOUS_DIRS = re.compile(r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\|\\ProgramData\\", re.IGNORECASE)

_STARTUP_FOLDERS = re.compile(
    r"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\|"
    r"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    re.IGNORECASE,
)
_SERVICE_IMAGE = re.compile(
    r"\\CurrentControlSet\\Services\\[^\\]+\\ImagePath|\\CurrentControlSet\\Services\\[^\\]+\\Parameters\\ServiceDll",
    re.IGNORECASE,
)
_APPINIT = re.compile(r"\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", re.IGNORECASE)
_ACC_FEATURE = re.compile(
    r"\\(sethc|utilman|narrator|magnify|osk|displayswitch|atbroker)\.exe", re.IGNORECASE,
)
_IFEO = re.compile(r"\\Image File Execution Options\\[^\\]+\\Debugger", re.IGNORECASE)
_NETSH_HELPER = re.compile(r"\bnetsh(?:\.exe)?\b[^\n]*\badd\s+helper\b", re.IGNORECASE)
_LOGON_SCRIPT = re.compile(
    r"\\CurrentVersion\\Windows\\Userinit|"
    r"\\CurrentVersion\\Policies\\Explorer\\Run\b|"
    r"\\Environment\\UserInitMprLogonScript|"
    r"\\Windows NT\\CurrentVersion\\Winlogon\\Shell\b",
    re.IGNORECASE,
)


class StartupFolderRule(BaseRule):
    rule_id = "startup_folder"
    name = "Startup Folder Persistence"
    description = (
        "A file was created in the Windows Startup folder - a persistent "
        "payload that executes at user logon."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1547.001"
    recommendation = (
        "Remove the startup entry, delete the dropped binary, and audit all "
        "startup locations on the host."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 11,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = facts.get("target_filename") or facts.get("target_object") or ""
            if not _STARTUP_FOLDERS.search(target):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"File created in Startup folder '{target}' by "
                        f"'{facts.get('image', '?')}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class ServiceImagePathPersistenceRule(BaseRule):
    rule_id = "service_image_path_persistence"
    name = "Service Image Path Persistence"
    description = (
        "A registry write changed a Windows service ImagePath or ServiceDll "
        "value - a persistent service that re-launches the attacker's binary."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1543.003"
    recommendation = (
        "Restore the original ImagePath, stop and remove the malicious "
        "service, and review how the registry write was performed."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
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
            if not _SERVICE_IMAGE.search(target):
                continue
            details = facts.get("details") or ""
            suspicious = bool(_SUSPICIOUS_DIRS.search(details)) or not details
            findings.append(
                self._result(
                    evidence=(
                        f"Registry {facts.get('event_type', 'SetValue')} on service "
                        f"ImagePath/ServiceDll '{target}' = '{details}' by "
                        f"'{facts.get('image', '?')}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                    confidence=min(0.95, self.confidence + (0.1 if suspicious else 0.0)),
                )
            )
        return findings


class AppInitDllRule(BaseRule):
    rule_id = "appinit_dlls"
    name = "AppInit_DLLs Persistence"
    description = (
        "The AppInit_DLLs registry value was modified - injected DLLs that "
        "load into every user-mode process at logon."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1546.010"
    recommendation = (
        "Remove the malicious DLL entry, delete the DLL, and enforce "
        "AppInit_DLLs integrity via application whitelisting."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
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
            if not _APPINIT.search(target):
                continue
            details = facts.get("details") or ""
            findings.append(
                self._result(
                    evidence=(
                        f"AppInit_DLLs set to '{details}' by '{facts.get('image', '?')}' "
                        f"as '{event.user}' (Event {event.event_id})."
                    ),
                    event_ids=[event.id],
                    confidence=min(0.95, self.confidence + (0.15 if details else 0.0)),
                )
            )
        return findings


class AccessibilityFeatureRule(BaseRule):
    rule_id = "accessibility_feature"
    name = "Accessibility Feature Backdoor"
    description = (
        "An accessibility binary (sethc, utilman, ...) was replaced or "
        "hijacked - a persistence technique that grants SYSTEM shells from "
        "the lock screen."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1546.008"
    recommendation = (
        "Restore the original accessibility binary from trusted media, "
        "disable sticky-keys logon access, and review the binary's provenance."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        # 1) File create (Sysmon 11) replacing an accessibility binary.
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([11, 1]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = facts.get("target_filename") or facts.get("image_path") or ""
            if not _ACC_FEATURE.search(target):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Accessibility binary '{target}' created by "
                        f"'{facts.get('image', '?')}' as '{event.user}' (Event {event.event_id})."
                    ),
                    event_ids=[event.id],
                )
            )

        # 2) Debugger registry value attached to an accessibility binary (IFEO).
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
            if not (_ACC_FEATURE.search(target) and _IFEO.search(target)):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"IFEO Debugger for accessibility binary '{target}' = "
                        f"'{facts.get('details', '?')}' by '{facts.get('image', '?')}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class IfeoDebuggerRule(BaseRule):
    rule_id = "ifeo_debugger"
    name = "IFEO Debugger Persistence"
    description = (
        "An Image File Execution Options Debugger value was set - a "
        "persistence and execution-flow hijack of any target binary."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1546.012"
    recommendation = (
        "Remove the Debugger value, identify the substituted binary, and "
        "review the writing process and its parent chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
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
            if not _IFEO.search(target):
                continue
            details = facts.get("details") or ""
            if not details:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"IFEO Debugger '{target}' = '{details}' by "
                        f"'{facts.get('image', '?')}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class NetshHelperRule(BaseRule):
    rule_id = "netsh_helper"
    name = "Netsh Helper DLL"
    description = (
        "netsh was used to register a helper DLL - a persistence technique "
        "that runs attacker code whenever netsh executes."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1546.007"
    recommendation = (
        "Remove the helper registration, delete the DLL, and audit netsh "
        "helper persistence across hosts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _NETSH_HELPER.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Netsh helper DLL registration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class LogonScriptRule(BaseRule):
    rule_id = "logon_script"
    name = "Logon Script Persistence"
    description = (
        "A registry value controlling logon-time scripts (Userinit, Shell, "
        "Run policies) was modified - persistence that executes at every logon."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1037.001"
    recommendation = (
        "Restore the original Userinit/Shell value, delete the referenced "
        "script, and audit logon script keys on all hosts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
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
            if not _LOGON_SCRIPT.search(target):
                continue
            details = facts.get("details") or ""
            suspicious = bool(_SUSPICIOUS_DIRS.search(details)) or bool(details and "C:\\Windows" not in details)
            findings.append(
                self._result(
                    evidence=(
                        f"Logon script key '{target}' = '{details}' by "
                        f"'{facts.get('image', '?')}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                    confidence=min(0.95, self.confidence + (0.15 if suspicious else 0.0)),
                )
            )
        return findings