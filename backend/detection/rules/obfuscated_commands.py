"""T1027 - Obfuscated Files or Information.

Detects encoded/obfuscated commands: Base64 encoded PowerShell,
double-encoded commands, compressed scripts, and other obfuscation
techniques used to evade detection.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

OBFUSCATION_PATTERNS = [
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "Base64 encoded command"),
    (r"-e\s+[A-Za-z0-9+/=]{20,}", "Short Base64 encoded command"),
    (r"frombase64string\(", "Base64 decode in command"),
    (r"invoke-expression.*-command\s.*\(", "IEX with dynamic command"),
    (r"iex\s*\(.*\)", "IEX with expression"),
    (r"compression\.gzipstream", "Gzip compression in command"),
    (r"-replace\s.*\\x[0-9a-f]{2}", "Hex character replacement obfuscation"),
    (r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", "Hex escape sequences"),
    (r"char\(\d+\)\s*\+", "Character code concatenation"),
    (r"-join\s.*char\(", "Join character codes"),
    (r"downloadstring.*\(", "DownloadString obfuscation"),
    (r"invoke-webrequest.*-usebasicparsing.*\|.*iex", "Download and execute"),
    (r"irm\s.*\|\s*iex", "Invoke-RestMethod pipe to IEX"),
    (r"iwr\s.*\|\s*iex", "Invoke-WebRequest pipe to IEX"),
    (r"bitsadmin.*\/transfer.*http", "BITS transfer from HTTP"),
    (r"certutil.*-urlcache.*-split.*-f", "CertUtil URL cache download"),
    (r"regsvr32.*\/s.*\/i.*http", "Regsvr32 scroptlet download"),
]

ENCODED_POWERSHELL_PATTERNS = [
    (r"powershell.*-[eE]\s+[A-Za-z0-9+/=]{50,}", "Encoded PowerShell command"),
    (r"pwsh.*-[eE]\s+[A-Za-z0-9+/=]{50,}", "Encoded pwsh command"),
    (r"powershell.*-ec\s+[A-Za-z0-9+/=]{50,}", "Short encoded PowerShell"),
]

SUSPICIOUS_PATTERNS = [
    (r"bypass.*-noprofile.*-noni.*-w\s*hidden", "Hidden PowerShell execution"),
    (r"-nop.*-w\s*hidden", "Hidden window with no profile"),
    (r"set\s.*=\s*['\"].*['\"].*\+\s*['\"]", "String concatenation in variable"),
    (r"cmd.*\/c.*echo.*\|.*cmd", "Piped cmd execution"),
    (r"for\s.*\/f.*delims.*do.*powershell", "For loop PowerShell execution"),
]


class ObfuscatedCommandRule(BaseRule):
    rule_id = "BARAQ-EVASION-001"
    title = "Obfuscated Command Execution"
    description = "Detects obfuscated or encoded command execution techniques"
    mitre_id = "T1027"
    severity = "high"
    confidence = 0.80

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in OBFUSCATION_PATTERNS + ENCODED_POWERSHELL_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if evidence:
            return DetectionResult(
                confidence=min(0.95, self.confidence + 0.05 * len(evidence)),
                severity="critical" if len(evidence) >= 3 else self.severity,
                mitre_id=self.mitre_id,
                evidence=evidence[:5],
                recommendation="Investigate for evasion technique usage",
            )

        return None
