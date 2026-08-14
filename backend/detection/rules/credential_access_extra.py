"""Rule set - Credential Access techniques (TA0006).

Covers OS credential dumping (T1003.001 LSASS / T1003.003 NTDS),
password-store theft (T1555), input capture (T1056.001), network sniffing
(T1040) and credential caching abuse (T1003.005).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from backend.detection.rules.base import BaseRule, DetectionResult

_LSASS_DUMP = re.compile(
    r"\b(?:procdump|rundll32|comsvcs|sqldumper|wermgr|dumpbin)\.exe\b[^\n]*\b(?:lsass|MiniDump)\b|"
    r"\bmimikatz(?:\.exe)?\b[^\n]*(?:sekurlsa|privilege::debug)|"
    r"\bsekurlsa::\b|"
    r"\b(?:taskmgr|Process Explorer)\b[^\n]*\b(?:lsass|dump)\b",
    re.IGNORECASE,
)
_NTDS_DUMP = re.compile(
    r"\bntdsutil(?:\.exe)?\b[^\n]*\b(?:activate|ifm|create)\b|"
    r"\bntds\.dit\b|"
    r"\besentutl(?:\.exe)?\b[^\n]*\bntds\b|"
    r"\bvssadmin(?:\.exe)?\b[^\n]*\bshadowcopy\b[^\n]*\bntds\b",
    re.IGNORECASE,
)
_PASSWORD_STORE = re.compile(
    r"\bcmdkey(?:\.exe)?\s+/list\b|"
    r"\bvaultcmd(?:\.exe)?\b|"
    r"\b(?:keymgr|vault)\b[^\n]*rundll32|"
    r"\bCredential Manager\b[^\n]*\b(?:open|view)|"
    r"\bGet-StoredCredential\b|"
    r"\bmimikatz(?:\.exe)?\b[^\n]*\b(?:dpapi|vault|sekurlsa)\b",
    re.IGNORECASE,
)
_KEYLOG = re.compile(
    r"\b(?:GetAsyncKeyState|SetWindowsHookEx|WH_KEYBOARD_LL|GetForegroundWindow)\b|"
    r"\bkeylogger\b|\b(?:refog|ardamax|spyrix)\b|"
    r"\bStart-Transcript\b[^\n]*\bkeylog\b",
    re.IGNORECASE,
)
_SNIFFING = re.compile(
    r"\b(?:wireshark|tcpdump|dumpcap|npcap|windump|ettercap|tshark)\b|"
    r"\bpktmon\b[^\n]*\b(?:start|trace)\b|"
    r"\bnetsh(?:\.exe)?\b[^\n]*\btrace\b[^\n]*\bstart\b",
    re.IGNORECASE,
)
_CACHED_CRED = re.compile(
    r"\bcmdkey(?:\.exe)?\b|"
    r"\breg(?:\.exe)?\s+(?:add|query)\b[^\n]*\\LS\b[^\n]*\b(?:CachePrimaryDomain|CachedLogonsCount)\b",
    re.IGNORECASE,
)


class LsassDumpRule(BaseRule):
    rule_id = "lsass_dump"
    name = "LSASS Memory Dump"
    description = (
        "A tool or technique was used to dump the LSASS process memory - "
        "harvesting plaintext credentials and hashes (Mimikatz sekurlsa, "
        "procdump -ma lsass, comsvcs MiniDump)."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1003.001"
    recommendation = (
        "Kill the dumping process, rotate all cached credentials, enable "
        "Credential Guard, and hunt for logons made with the stolen hashes."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _LSASS_DUMP.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"LSASS dump by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class NtdsDumpRule(BaseRule):
    rule_id = "ntds_dump"
    name = "NTDS.dit Dump / Extraction"
    description = (
        "Active Directory database access via ntdsutil, esentutl or shadow "
        "copy - extracting the domain credential database."
    )
    severity = "critical"
    confidence = 0.85
    mitre_id = "T1003.003"
    recommendation = (
        "Assume full domain compromise: reset KRBTGT twice, rotate all "
        "admin and service account passwords, and rebuild compromised "
        "domain controllers if needed."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _NTDS_DUMP.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"NTDS.dit dump by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class PasswordStoreTheftRule(BaseRule):
    rule_id = "password_store_theft"
    name = "Password Store Enumeration"
    description = (
        "Credential Manager, DPAPI vaults or Windows password stores were "
        "enumerated/exported - harvesting stored credentials."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1555"
    recommendation = (
        "Rotate stored credentials, clear Credential Manager entries, "
        "enable Credential Guard, and review where the harvested "
        "credentials were used."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _PASSWORD_STORE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Password-store enumeration by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class KeyloggingRule(BaseRule):
    rule_id = "keylogging"
    name = "Keystroke Capture"
    description = (
        "Windows hooking APIs or known keylogger utilities were invoked - "
        "capturing keystrokes to steal credentials."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1056.001"
    recommendation = (
        "Terminate the capturing process, rotate credentials typed on the "
        "host since capture began, and review the parent process chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _KEYLOG.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Keystroke capture by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class NetworkSniffingRule(BaseRule):
    rule_id = "network_sniffing"
    name = "Network Sniffing"
    description = (
        "A packet-capture tool (Wireshark, tcpdump, pktmon, netsh trace) "
        "was started - sniffing cleartext credentials on the wire."
    )
    severity = "medium"
    confidence = 0.65
    mitre_id = "T1040"
    recommendation = (
        "Stop the capture, review captured sessions for cleartext "
        "credentials, and restrict packet-capture tooling to approved "
        "administrators."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SNIFFING.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Packet capture by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class CachedCredentialsRule(BaseRule):
    rule_id = "cached_credentials"
    name = "Cached Credential Access"
    description = (
        "Cached logon credentials were enumerated or their cache limits "
        "modified - prelude to offline cracking of cached hashes."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1003.005"
    recommendation = (
        "Review the cache size configuration, rotate affected account "
        "passwords, and monitor for hash-cracking tooling on the host."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _CACHED_CRED.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Cached credential access by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings