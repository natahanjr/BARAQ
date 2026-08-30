"""Rules - process-level abuse: DLL side-loading (T1574.002), process
injection (T1055), access-token manipulation (T1134) and PrintNightmare
spooler abuse (T1068).

Uses Sysmon image-load / CreateRemoteThread events and command-line
indicators from process and PowerShell telemetry.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

_SYSTEM32 = re.compile(r"\\Windows\\(?:System32|SysWOW64|system32)\\", re.IGNORECASE)


def _facts(event) -> dict:
    return (event.raw_json or {}).get("facts", {}) if event.raw_json else {}


class DllSideloadingRule(BaseRule):
    rule_id = "dll_sideloading"
    name = "DLL Side-Loading"
    description = (
        "A trusted Windows process loaded a module from a user-writable "
        "directory - a malicious DLL riding the search path of a legitimate, "
        "signed executable."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1574.002"
    recommendation = (
        "Remove the malicious DLL, apply application whitelisting, enforce "
        "DLL load-order hardening and signature verification, and hunt for "
        "the payload that dropped the DLL."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 7,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        for event in rows:
            facts = _facts(event)
            module = facts.get("image_loaded") or ""
            source = facts.get("source_image") or facts.get("image") or ""
            if not module:
                continue
            if not _SYSTEM32.search(module) and _SYSTEM32.search(source):
                findings.append(
                    self._result(
                        evidence=(
                            f"System process '{source}' loaded module "
                            f"'{module}' from outside System32 - DLL "
                            f"side-loading indicator (user '{event.user}')."
                        ),
                        event_ids=[event.id],
                    )
                )
        return findings


class ProcessInjectionRule(BaseRule):
    rule_id = "process_injection"
    name = "Process Injection (CreateRemoteThread)"
    description = (
        "A process created a remote thread in another process (Sysmon 8) - "
        "the classic process-injection primitive, especially when targeting "
        "LSASS or other privileged processes."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1055"
    recommendation = (
        "Identify the injecting parent process and payload, isolate the host, "
        "enable Credential Guard and PPL for LSASS, and review the origin of "
        "the injected thread."
    )

    _CMDLINE = re.compile(
        r"\binvoke-atomic\b[^\n]*?createremotethread\b|"
        r"\bcreateremotethread\b[^\n]*(?:inject|remote|target)|"
        r"\binvoke-injection\b|\bprocesshacker\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Process-injection tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )

        for event in self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 8,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all():
            facts = _facts(event)
            target = facts.get("target_image") or "?"
            source = facts.get("source_image") or "?"
            findings.append(
                self._result(
                    evidence=(
                        f"CreateRemoteThread (Sysmon 8): '{source}' injected a "
                        f"thread into '{target}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                )
            )
        return findings


class TokenManipulationRule(BaseRule):
    rule_id = "token_manipulation"
    name = "Access Token Manipulation"
    description = (
        "Token impersonation / duplication tooling (mimikatz token::, "
        "Invoke-TokenManipulation, SeDebugPrivilege abuse) - privilege "
        "escalation without a new logon."
    )
    severity = "high"
    confidence = 0.6
    mitre_id = "T1134"
    recommendation = (
        "Kill the token-stealing process, revoke SeDebugPrivilege for "
        "unnecessary accounts, enable Credential Guard, and review the "
        "token's original owner for compromise."
    )

    _CMDLINE = re.compile(
        r"token::elevate\b|token::impersonate\b|token::whoami\b|token::revert\b|"
        r"\bimpersonate-user\b|\binvoke-tokenmanipulation\b|"
        r"\bsteal\s+token\b|\bstealtoken\b|\bseassignprimarytokenprivilege\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Token manipulation tooling by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class PrintNightmareRule(BaseRule):
    rule_id = "printer_spooler_abuse"
    name = "Print Spooler Exploitation (PrintNightmare)"
    description = (
        "Print driver installation via printui.dll / Add-PrinterDriver or "
        "PrintNightmare exploit tooling - the spooler path used for remote "
        "code execution as SYSTEM (CVE-2021-34527)."
    )
    severity = "critical"
    confidence = 0.8
    mitre_id = "T1068"
    recommendation = (
        "Isolate the host immediately, check for spoolsv.exe child processes "
        "and driver DLLs, apply the print spooler hardening (disable the "
        "spooler where unused), and hunt for the delivered payload."
    )

    _CMDLINE = re.compile(
        r"printui\.dll,PrintUIEntry\b[^\n]*?(?:/ia\b|/if\b)|"
        r"\badd-printerdriver\b|\binstallprinterdriver\b|"
        r"\binvoke-nightmare\b|\bprintnightmare\b|\bcve-2021-34527\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"PrintNightmare-style spooler abuse by '{user}' "
                        f"({label}). Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
