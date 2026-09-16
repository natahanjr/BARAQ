"""T1562.001 - Impair Defenses: Disable or Modify Tools.

Detects attempts to disable or modify security tools:
stopping antivirus services, disabling Defender, tampering
with EDR agents, and modifying security configurations.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

DISABLE_COMMANDS = [
    (r"sc\s+stop\s+windefend", "Stopping Windows Defender service"),
    (r"sc\s+config\s+windefend\s+start=", "Disabling Windows Defender startup"),
    (r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true", "Disabling Defender real-time protection"),
    (r"Set-MpPreference\s+-DisableIOAVProtection", "Disabling Defender IOAV protection"),
    (r"Set-MpPreference\s+-DisableBehaviorMonitoring", "Disabling Defender behavior monitoring"),
    (r"Set-MpPreference\s+-DisableBlockAtFirstSeen", "Disabling block at first seen"),
    (r"Set-MpPreference\s+-DisableScriptScanning", "Disabling script scanning"),
    (r"Set-MpPreference\s+-ExclusionPath", "Adding Defender exclusion path"),
    (r"Set-MpPreference\s+-ExclusionProcess", "Adding Defender exclusion process"),
    (r"Set-MpPreference\s+-ExclusionExtension", "Adding Defender exclusion extension"),
    (r"Uninstall-WindowsFeature\s+-Name\s+Windows-Defender", "Uninstalling Windows Defender"),
    (r"Stop-Process.*-Name.*MsMpEng", "Killing Defender process"),
    (r"taskkill.*MsMpEng", "Killing Defender process"),
    (r"sc\s+stop\s+Sense", "Stopping Defender ATP service"),
    (r"sc\s+stop\s+SenseIR", "Stopping Defender IR service"),
    (r"sc\s+stop\s+SenseNdr", "Stopping Defender NDR service"),
    (r"sc\s+stop\s+SecurityHealthService", "Stopping Security Health service"),
    (r"sc\s+stop\s+WindowsDefenderService", "Stopping Windows Defender service"),
    (r"net\s+stop\s+windefend", "Stopping Windows Defender via net"),
    (r"sc\s+delete\s+windefend", "Deleting Windows Defender service"),
    (r"powershell.*Remove-WindowsDefender", "Removing Windows Defender"),
    (r"sc\s+stop\s+Cylance", "Stopping Cylance EDR"),
    (r"sc\s+stop\s+CrowdStrike", "Stopping CrowdStrike EDR"),
    (r"sc\s+stop\s+SentinelAgent", "Stopping SentinelOne EDR"),
    (r"sc\s+stop\s+Tanium", "Stopping Tanium agent"),
    (r"sc\s+stop\s+cb", "Stopping Carbon Black"),
    (r"sc\s+stop\s+Traps", "Stopping Palo Alto Traps"),
    (r"sc\s+stop\s+CSFalconService", "Stopping CrowdStrike Falcon"),
    (r"sc\s+stop\s+SEPMasterService", "Stopping Symantec EP"),
    (r"sc\s+stop\s+ccEvtMgr", "Stopping Symantec Event Manager"),
    (r"sc\s+stop\s+SNAC", "Stopping Symantec Network"),
]

FIREWALL_DISABLE = [
    (r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off", "Disabling all firewall profiles"),
    (r"netsh\s+advfirewall\s+set\s+domainprofile\s+state\s+off", "Disabling domain firewall"),
    (r"netsh\s+advfirewall\s+set\s+privateprofile\s+state\s+off", "Disabling private firewall"),
    (r"netsh\s+advfirewall\s+set\s+publicprofile\s+state\s+off", "Disabling public firewall"),
    (r"Set-NetFirewallProfile\s+-Profile\s+\*\s+-Enabled\s+False", "Disabling firewall via PowerShell"),
]


class DisableSecurityToolsRule(BaseRule):
    rule_id = "BARAQ-EVASION-004"
    title = "Security Tool Disabling Attempt"
    description = "Detects attempts to disable or modify security tools and defenses"
    mitre_id = "T1562.001"
    severity = "critical"
    confidence = 0.90

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in DISABLE_COMMANDS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in FIREWALL_DISABLE:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        return DetectionResult(
            confidence=min(0.98, self.confidence + 0.02 * len(evidence)),
            severity=self.severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="CRITICAL: Security tools disabled. Investigate immediately.",
        )
