"""T1566 - Phishing.

Detects phishing indicators: suspicious email attachments,
malicious links in emails, macro-enabled documents, and
social engineering lures.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

PHISHING_INDICATORS = [
    (r"outlook.*\.exe.*\/a\s+.*\.(doc|xls|ppt|pdf|zip|rar|iso|img|lnk|url|hta)", "Email with suspicious attachment launched"),
    (r"winword\.exe.*\.(docm|xlsm|pptm)", "Office macro-enabled document opened"),
    (r"excel\.exe.*\.(docm|xlsm)", "Excel macro-enabled document opened"),
    (r"mshta.*http", "MSHTA executing remote script"),
    (r"wmic.*process\s+call\s+create.*http", "WMI remote process creation"),
    (r"powershell.*download.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "PowerShell downloading document"),
    (r"powershell.*invoke-webrequest.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "PowerShell downloading document via WebRequest"),
    (r"powershell.*start-bitstransfer.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "BITS downloading document"),
    (r"certutil.*-urlcache.*-split.*-f.*http.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "CertUtil downloading document"),
    (r"bitsadmin.*\/transfer.*http.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "BITS transferring document"),
    (r"curl.*-o.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "Curl downloading document"),
    (r"wget.*\.(doc|xls|pdf|zip|rar|iso|img|lnk|hta)", "Wget downloading document"),
    (r"powershell.*open.*\.lnk", "PowerShell opening LNK file"),
    (r"powershell.*start-process.*\.hta", "PowerShell launching HTA file"),
    (r"rundll32.*url\.dll", "Rundll32 URL execution"),
    (r"rundll32.*mshtml.*http", "Rundll32 remote HTML execution"),
    (r"regsvr32.*\/s.*\/i.*http", "Regsvr32 scroptlet download"),
    (r"msiexec.*http", "MSI installer from HTTP"),
    (r"msiexec.*\/i.*http", "MSI installation from HTTP"),
]

MACRO_PATTERNS = [
    (r"Auto_Open", "Auto-open macro detected"),
    (r"Document_Open", "Document open macro detected"),
    (r"Workbook_Open", "Workbook open macro detected"),
    (r"AutoOpen", "AutoOpen macro detected"),
    (r"AutoExec", "AutoExec macro detected"),
    (r"AutoExit", "AutoExit macro detected"),
    (r"AutoClose", "AutoClose macro detected"),
    (r"AutoNew", "AutoNew macro detected"),
    (r"auto_open", "Auto-open macro (lowercase)"),
    (r"document_open", "Document open macro (lowercase)"),
]


class PhishingRule(BaseRule):
    rule_id = "BARAQ-INITIAL-003"
    title = "Phishing Attempt Detected"
    description = "Detects phishing indicators including malicious attachments and macro documents"
    mitre_id = "T1566"
    severity = "high"
    confidence = 0.75

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in PHISHING_INDICATORS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in MACRO_PATTERNS:
            if pattern.lower() in cmdline:
                evidence.append(desc)

        if not evidence:
            return None

        severity = "critical" if len(evidence) >= 3 else self.severity

        return DetectionResult(
            confidence=min(0.95, self.confidence + 0.05 * len(evidence)),
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate for phishing campaign and user awareness",
        )
