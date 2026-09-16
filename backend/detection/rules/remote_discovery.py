"""T1018 - Remote System Discovery.

Detects discovery commands used to enumerate remote systems,
hosts, and network topology: net view, net group, nltest,
dsquery, ping sweeps, and ARP scanning.
"""

from __future__ import annotations

from backend.detection.rules.base import BaseRule, DetectionResult

DISCOVERY_COMMANDS = [
    ("net view", "Network share enumeration"),
    ("net group \"domain admins\"", "Domain admin enumeration"),
    ("net group \"enterprise admins\"", "Enterprise admin enumeration"),
    ("net localgroup administrators", "Local admin enumeration"),
    ("nltest /dclist", "Domain controller enumeration"),
    ("nltest /domain_trusts", "Domain trust enumeration"),
    ("dsquery", "Active Directory query"),
    ("dsquery computer", "Computer object enumeration"),
    ("dsquery user", "User object enumeration"),
    ("dsquery group", "Group object enumeration"),
    ("adfind", "AD enumeration tool"),
    ("sharpdog", "AD enumeration tool"),
    ("bloodhound", "AD attack path tool"),
    ("sharpbloodhound", "AD attack path tool"),
    ("ping -n", "Ping sweep"),
    ("for /l %i in (1,1,254)", "IP range scan"),
    ("arp -a", "ARP table enumeration"),
    ("nbtstat -a", "NetBIOS remote name cache"),
    ("nslookup", "DNS enumeration"),
    ("whoami /priv", "Privilege enumeration"),
    ("whoami /groups", "Group membership enumeration"),
    ("systeminfo", "System information gathering"),
    ("ipconfig /all", "Network configuration enumeration"),
    ("net statistics workstation", "Workstation statistics"),
    ("net config workstation", "Workstation configuration"),
    ("tasklist /svc", "Service enumeration"),
    ("netsh advfirewall", "Firewall rule enumeration"),
    ("reg query hklm\\software\\microsoft\\windows\\currentversion", "Registry enumeration"),
]


class RemoteDiscoveryRule(BaseRule):
    rule_id = "BARAQ-DISC-001"
    title = "Remote System Discovery"
    description = "Detects commands used to discover remote systems and network topology"
    mitre_id = "T1018"
    severity = "medium"
    confidence = 0.70

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []
        for cmd, desc in DISCOVERY_COMMANDS:
            if cmd.lower() in cmdline:
                evidence.append(f"{desc}: {cmd}")

        if not evidence:
            return None

        severity = "high" if len(evidence) >= 3 else self.severity
        confidence = min(0.95, self.confidence + 0.05 * len(evidence))

        return DetectionResult(
            confidence=confidence,
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Determine if discovery activity is legitimate admin work",
        )
