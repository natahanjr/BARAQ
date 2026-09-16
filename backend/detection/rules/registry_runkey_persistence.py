"""T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys.

Detects suspicious registry Run/RunOnce key modifications for
persistence, including new entries, executable paths in temp
directories, and suspicious binary names.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

RUN_KEY_PATHS = [
    r"\\software\\microsoft\\windows\\currentversion\\run",
    r"\\software\\microsoft\\windows\\currentversion\\runonce",
    r"\\software\\microsoft\\windows\\currentversion\\runonceex",
    r"\\software\\microsoft\\windows\\currentversion\\runservices",
    r"\\software\\microsoft\\windows\\currentversion\\runservicesonce",
    r"\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
    r"\\software\\microsoft\\windows nt\\currentversion\\winlogon",
    r"\\software\\microsoft\\windows nt\\currentversion\\windows\\load",
    r"\\software\\microsoft\\windows nt\\currentversion\\windows\\run",
    r"\\software\\microsoft\\windows\\currentversion\\explorer\\shell folders",
    r"\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
    r"\\software\\microsoft\\windows\\currentversion\\explorer\\browser helper objects",
]

SUSPICIOUS_PATTERNS = [
    (r"powershell.*-w\s*hidden", "Hidden PowerShell in autorun"),
    (r"powershell.*-enc", "Encoded PowerShell in autorun"),
    (r"cmd\.exe.*/c", "CMD execution in autorun"),
    (r"rundll32", "Rundll32 in autorun"),
    (r"mshta", "MSHTA in autorun"),
    (r"regsvr32", "Regsvr32 in autorun"),
    (r"\\temp\\", "Binary in temp directory"),
    (r"\\appdata\\local\\temp\\", "Binary in AppData temp"),
    (r"\\users\\public\\", "Binary in public folder"),
    (r"\\programdata\\", "Binary in ProgramData"),
    (r"\\downloads\\", "Binary in Downloads"),
    (r"\\desktop\\", "Binary on Desktop"),
    (r"\\startup\\", "Binary in Startup folder"),
    (r"http://", "HTTP URL in autorun"),
    (r"https://", "HTTPS URL in autorun"),
    (r"\\\.scr", "Screensaver executable"),
    (r"\\\.pif", "PIF executable"),
    (r"\\\.com", "COM executable"),
    (r"\\\.vbs", "VBScript in autorun"),
    (r"\\\.js", "JavaScript in autorun"),
    (r"\\\.wsf", "Windows Script in autorun"),
    (r"\\\.hta", "HTA in autorun"),
]


class RegistryRunKeyRule(BaseRule):
    rule_id = "BARAQ-PERSIST-011"
    title = "Registry Run Key Persistence"
    description = "Detects suspicious registry Run key modifications for persistence"
    mitre_id = "T1547.001"
    severity = "high"
    confidence = 0.80

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        is_registry_write = any(
            term in cmdline
            for term in ["reg add", "reg.exe add", "set-itemproperty", "new-itemproperty"]
        )
        if not is_registry_write:
            return None

        evidence = []
        for path in RUN_KEY_PATHS:
            if path.replace("\\\\", "\\") in cmdline or path.replace("\\", "\\\\") in cmdline:
                evidence.append(f"Registry Run key modification: {path}")
                break

        if not evidence:
            for path in RUN_KEY_PATHS:
                if any(part in cmdline for part in path.split("\\")):
                    evidence.append(f"Registry persistence key: {path}")
                    break

        if not evidence:
            return None

        for pattern, desc in SUSPICIOUS_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        severity = "critical" if len(evidence) >= 3 else self.severity

        return DetectionResult(
            confidence=min(0.95, self.confidence + 0.03 * len(evidence)),
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Review registry Run key for persistence mechanism",
        )
