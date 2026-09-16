"""T1003 - OS Credential Dumping.

Detects credential dumping techniques: LSASS memory access,
SAM/SECURITY/SYSTEM hive access, DCSync, and ntds.dit access.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

CREDENTIAL_DUMP_TECHNIQUES = [
    (r"sekurlsa::logonpasswords", "Mimikatz logon passwords dump"),
    (r"sekurlsa::wdigest", "Mimikatz WDigest credential dump"),
    (r"sekurlsa::kerberos", "Mimikatz Kerberos credential dump"),
    (r"sekurlsa::msv", "Mimikatz MSV credential dump"),
    (r"sekurlsa::tspkg", "Mimikatz TsPkg credential dump"),
    (r"sekurlsa::credman", "Mimikatz Credential Manager dump"),
    (r"lsadump::sam", "Mimikatz SAM dump"),
    (r"lsadump::lsa", "Mimikatz LSA dump"),
    (r"lsadump::dcsync", "Mimikatz DCSync attack"),
    (r"lsadump::trust", "Mimikatz trust dump"),
    (r"kerberos::golden", "Mimikatz Golden Ticket creation"),
    (r"kerberos::silver", "Mimikatz Silver Ticket creation"),
    (r"kerberos::ptt", "Mimikatz Pass-the-Ticket"),
    (r"kerberos::ptk", "Mimikatz Pass-the-Key"),
    (r"vault::cred", "Mimikatz vault credential dump"),
    (r"vault::list", "Mimikatz vault listing"),
    (r"crypto::capi", "Mimikatz CryptoAPI hook"),
    (r"crypto::cng", "Mimikatz CNG hook"),
    (r"privilege::debug", "Mimikatz debug privilege"),
    (r"token::elevate", "Mimikatz token elevation"),
]

REGISTRY_DUMP = [
    (r"reg\s+save\s+hklm\\sam", "SAM hive export"),
    (r"reg\s+save\s+hklm\\security", "SECURITY hive export"),
    (r"reg\s+save\s+hklm\\system", "SYSTEM hive export"),
    (r"reg\s+save\s+hku\\", "User hive export"),
    (r"reg\s+export\s+hklm\\sam", "SAM hive export via reg export"),
    (r"reg\s+export\s+hklm\\security", "SECURITY hive export via reg export"),
    (r"copy.*c:\\windows\\ntds\\ntds.dit", "ntds.dit copy"),
    (r"copy.*c:\\windows\\system32\\config\\sam", "SAM file copy"),
    (r"copy.*c:\\windows\\system32\\config\\security", "SECURITY file copy"),
    (r"copy.*c:\\windows\\system32\\config\\system", "SYSTEM file copy"),
    (r"ntdsutil", "NTDSutil (DCSync/DC maintenance)"),
    (r"vssadmin.*create shadow.*c:", "VSS shadow copy for file access"),
    (r"esentutl.*\/y.*sam", "ESentutl SAM file copy"),
    (r"esentutl.*\/y.*security", "ESEntutl SECURITY file copy"),
]

TOOLS = [
    "mimikatz",
    "mimilib",
    "mimidrv",
    "procdump",
    "procdump64",
    "nanodump",
    "handlekatz",
    "pypykatz",
    "SharpDump",
    "SafetyKatz",
    "Dumpert",
    "DirectSyscall",
    "rundll32.exe comsvcs.dll",
]


class CredentialDumpingRule(BaseRule):
    rule_id = "BARAQ-CRED-002"
    title = "OS Credential Dumping"
    description = "Detects credential dumping techniques targeting LSASS, SAM, and AD"
    mitre_id = "T1003"
    severity = "critical"
    confidence = 0.90

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for tool in TOOLS:
            if tool.lower() in cmdline:
                evidence.append(f"Credential dumping tool: {tool}")

        for pattern, desc in CREDENTIAL_DUMP_TECHNIQUES:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for pattern, desc in REGISTRY_DUMP:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        return DetectionResult(
            confidence=min(0.99, self.confidence + 0.01 * len(evidence)),
            severity=self.severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="CRITICAL: Credential dumping detected. Isolate host immediately.",
        )
