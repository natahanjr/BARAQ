"""T1059 - Command and Scripting Interpreter.

Detects suspicious scripting interpreter usage: PowerShell,
cmd.exe, wscript, cscript, and script execution from unusual
locations or with suspicious arguments.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_SCRIPT_PATTERNS = [
    (r"powershell.*-nop.*-w\s*hidden.*-e", "Hidden encoded PowerShell"),
    (r"powershell.*-noni.*-nop.*-w\s*hidden", "Hidden non-interactive PowerShell"),
    (r"powershell.*bypass.*-noprofile", "Bypass execution policy PowerShell"),
    (r"powershell.*-executionpolicy\s+bypass", "Execution policy bypass"),
    (r"powershell.*-command.*frombase64string", "Base64 decoded PowerShell"),
    (r"powershell.*-command.*invoke-expression", "IEX in PowerShell"),
    (r"powershell.*iex\s*\(", "IEX call in PowerShell"),
    (r"powershell.*iwr\s.*\|\s*iex", "Download and execute PowerShell"),
    (r"powershell.*irm\s.*\|\s*iex", "Download and execute PowerShell"),
    (r"powershell.*downloadstring\s*\(", "DownloadString in PowerShell"),
    (r"powershell.*invoke-webrequest.*\|.*iex", "Download pipe to IEX"),
    (r"cmd\.exe.*/c.*echo.*\|.*cmd", "Piped cmd execution"),
    (r"cmd\.exe.*/c.*type.*\|.*cmd", "Type pipe cmd execution"),
    (r"cmd\.exe.*/c.*more.*\|.*cmd", "More pipe cmd execution"),
    (r"wscript.*http", "WScript executing remote script"),
    (r"cscript.*http", "CScript executing remote script"),
    (r"wscript.*\\\\.*\.vbs", "WScript executing VBS from UNC"),
    (r"cscript.*\\\\.*\.vbs", "CScript executing VBS from UNC"),
    (r"mshta.*http", "MSHTA executing remote content"),
    (r"mshta.*vbscript", "MSHTA executing VBScript"),
    (r"mshta.*javascript", "MSHTA executing JavaScript"),
    (r"rundll32.*javascript", "Rundll32 executing JavaScript"),
    (r"regsvr32.*\/s.*\/i.*scrobj", "Regsvr32 scriptlet execution"),
    (r"installutil.*\/logfile=.*\/assemblytype=", "InstallUtil assembly execution"),
    (r"msbuild.*\/p:prebuildevent", "MSBuild prebuild event execution"),
    (r"msbuild.*\/t:build.*\/p:", "MSBuild project execution"),
    (r"regasm.*\/logfile=.*\/assemblytype=", "RegASM assembly execution"),
    (r"regsvcs.*\/logfile=.*\/assemblytype=", "RegSvcs assembly execution"),
    (r"cmstp.*\/s", "CMSTP silent install"),
    (r"pcalua.*-a.*http", "PCALUA executing remote content"),
    (r"msiexec.*\/q.*http", "MSI quiet install from HTTP"),
    (r"msiexec.*\/quiet.*http", "MSI quiet install from HTTP"),
    (r"msiexec.*\/i.*http", "MSI install from HTTP"),
    (r"certutil.*-urlcache.*-split.*-f.*http", "CertUtil downloading from HTTP"),
    (r"certutil.*-decode", "CertUtil decoding base64"),
    (r"bitsadmin.*\/transfer.*http", "BITS transfer from HTTP"),
]


class ScriptingInterpreterRule(BaseRule):
    rule_id = "BARAQ-EXEC-003"
    title = "Suspicious Scripting Interpreter Usage"
    description = "Detects suspicious usage of scripting interpreters for execution"
    mitre_id = "T1059"
    severity = "high"
    confidence = 0.80

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in SUSPICIOUS_SCRIPT_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        severity = "critical" if len(evidence) >= 3 else self.severity

        return DetectionResult(
            confidence=min(0.95, self.confidence + 0.03 * len(evidence)),
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate scripting interpreter for malicious execution",
        )
