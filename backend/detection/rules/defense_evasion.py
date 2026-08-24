"""Rules - defense evasion: Safe Mode boot tampering (T1562.001),
AMSI / Defender bypass (T1562.001) and rogue root-certificate installation
(T1553.004).

All three are command-line / script-block detections over 4688 process
creation, 4104 PowerShell script blocks and process snapshots.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from backend.detection.rules.base import BaseRule, DetectionResult


class SafeBootTamperingRule(BaseRule):
    rule_id = "safeboot_tampering"
    name = "Safe Mode Boot Tampering"
    description = (
        "Boot configuration was changed to Safe Mode (bcdedit safeboot) - "
        "attackers reboot into Safe Mode to launch tools with security "
        "software disabled or degraded."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1562.001"
    recommendation = (
        "Reverse the boot change (bcdedit /deletevalue safeboot), verify "
        "security agents restarted cleanly, and treat the change as an active "
        "defense-evasion campaign requiring a full hunt."
    )

    _CMDLINE = re.compile(
        r"\bbcdedit\b[^\n]*?\bsafeboot\b|"
        r"\bbootcfg\b[^\n]*?\bsafeboot\b|"
        r"\bsafeboot\s+(?:minimal|network|alternateshell)\b|"
        r"\bmsconfig\b[^\n]*?\b/boot\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Safe Mode boot tampering by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class AmsiBypassRule(BaseRule):
    rule_id = "amsi_bypass"
    name = "AMSI / Antivirus Bypass"
    description = (
        "AMSI bypass strings or Defender real-time protection disabling "
        "switches in a command line / PowerShell script block - the attacker "
        "is neutralizing in-memory scanning and AV."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1562.001"
    recommendation = (
        "Treat as active defense evasion: review the full script, re-enable "
        "Defender real-time protection / tamper protection, and investigate "
        "what payload was executed while AV was disabled."
    )

    _CMDLINE = re.compile(
        r"amsiinitfailed|amsicontext|amsiscanbuffer|amsiutils|"
        r"\bamsi\b[^\n]{0,40}\bbypass\b|"
        r"-disablerealtimemonitoring\b|-disableioavprotection\b|-disablescriptscanning\b|"
        r"\bset-mppreference\b[^\n]*?-disablerealtime\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"AMSI / AV bypass by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class CertificateSpoofingRule(BaseRule):
    rule_id = "certificate_spoofing"
    name = "Rogue Root Certificate Installation"
    description = (
        "A certificate was added to the Root store or a new self-signed "
        "certificate was created (certutil -addstore, Import-Certificate, "
        "New-SelfSignedCertificate) - trust subversion so malicious code and "
        "TLS traffic appear legitimate."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1553.004"
    recommendation = (
        "Remove the rogue certificate from the Root store, revoke trust, "
        "audit what was signed or intercepted since installation, and review "
        "the installing user's session."
    )

    _CMDLINE = re.compile(
        r"\bcertutil\b[^\n]*?(?:-addstore\b|-importpfx\b|-importpem\b)|"
        r"\bcertutil\b[^\n]*?-store\b[^\n]*?\broot\b|"
        r"\bimport-certificate\b[^\n]*?(?:certstorelocation|root)|"
        r"\bnew-selfsignedcertificate\b|"
        r"\bcertmgr\b[^\n]*?/add\b",
        re.IGNORECASE,
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not self._CMDLINE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Certificate trust subversion by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
