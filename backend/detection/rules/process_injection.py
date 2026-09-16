"""T1055 - Process Injection.

Detects process injection techniques: DLL injection, process
hollowing, thread execution hijacking, and APC queue injection.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

INJECTION_TECHNIQUES = [
    (r"createremotethread", "Remote thread creation (DLL injection)"),
    (r"ntwritevirtualmemory", "Virtual memory write (process hollowing)"),
    (r"zwwritevirtualmemory", "Virtual memory write (process hollowing)"),
    (r"ntmapviewofsection", "Section mapping (process hollowing)"),
    (r"zwmapviewofsection", "Section mapping (process hollowing)"),
    (r"ntunmapviewofsection", "Section unmapping (process hollowing)"),
    (r"ntresumeThread", "Thread resumption (process hollowing)"),
    (r"ntqueueapcthread", "APC queue injection"),
    (r"zwqueueapcthread", "APC queue injection"),
    (r"setthreadcontext", "Thread context modification"),
    (r"ntprotectvirtualmemory", "Memory protection change"),
    (r"openprocess.*0x1f0fff", "Full process access rights"),
    (r"openprocess.*process_all_access", "Full process access"),
    (r"writeprocessmemory", "Process memory write"),
    (r"rtlcreateuserthread", "Remote thread creation"),
    (r"createremotethreadex", "Remote thread creation with args"),
    (r"npptool", "Process injection tool"),
    (r"mavinject", "MAVInject injection tool"),
    (r"procmon", "Process Monitor (recon)"),
]

SUSPICIOUS_INJECTORS = [
    "powershell",
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "installutil",
    "msbuild",
    "regasm",
    "regsvcs",
    "cmstp",
    "pcalua",
    "msiexec",
]

INJECTION_TARGETS = [
    "lsass",
    "svchost",
    "csrss",
    "winlogon",
    "services",
    "explorer",
    "chrome",
    "firefox",
    "msedge",
    "outlook",
    "teams",
    "slack",
]


class ProcessInjectionRule(BaseRule):
    rule_id = "BARAQ-EVASION-003"
    title = "Process Injection Detected"
    description = "Detects process injection techniques including DLL injection and process hollowing"
    mitre_id = "T1055"
    severity = "critical"
    confidence = 0.85

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in INJECTION_TECHNIQUES:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        parent = (event.get("parent_name") or "").lower()
        for injector in SUSPICIOUS_INJECTORS:
            if injector in parent:
                evidence.append(f"Injection from suspicious parent: {injector}")
                break

        for target in INJECTION_TARGETS:
            if target in cmdline:
                evidence.append(f"Injection targeting: {target}")
                break

        severity = "critical" if any("lsass" in e.lower() for e in evidence) else self.severity
        confidence = min(0.98, self.confidence + 0.03 * len(evidence))

        return DetectionResult(
            confidence=confidence,
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate for process injection attack",
        )
