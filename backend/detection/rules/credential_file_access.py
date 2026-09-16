"""T1552.001 - Unsecured Credentials: Credentials In Files.

Detects processes reading files that commonly contain credentials:
password files, config files with embedded secrets, .env files,
SSH keys, browser credential stores.
"""

from __future__ import annotations

from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_FILE_PATTERNS = [
    "appdata\\local\\google\\chrome\\user data\\default\\login data",
    "appdata\\local\\google\\chrome\\user data\\default\\cookies",
    "appdata\\roaming\\mozilla\\firefox\\profiles\\",
    "appdata\\local\\microsoft\\edge\\user data\\default\\login data",
    ".ssh\\id_rsa",
    ".ssh\\authorized_keys",
    "desktop\\*.kdbx",
    "documents\\*password*",
    ".env",
    "wp-config.php",
    "web.config",
    "appsettings.json",
    "connectionstrings.config",
    "credentials.xml",
    "secrets.yml",
    "vault.json",
]

SUSPICIOUS_TOOLS = [
    "mimikatz",
    "sekurlsa",
    "vaultcmd",
    "cmdkey",
    "dpapi",
    "keychain",
    "keepass",
    "1password",
    "bitwarden",
]


class CredentialFileAccessRule(BaseRule):
    rule_id = "BARAQ-CRED-001"
    title = "Credential File Access"
    description = "Process accessed files commonly containing credentials"
    mitre_id = "T1552.001"
    severity = "high"
    confidence = 0.75

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        path = (event.get("path") or "").lower()

        for tool in SUSPICIOUS_TOOLS:
            if tool in cmdline:
                return DetectionResult(
                    confidence=0.9,
                    severity="critical",
                    mitre_id=self.mitre_id,
                    evidence=[f"Suspicious tool in command line: {tool}"],
                    recommendation="Investigate credential theft activity",
                )

        for pattern in SUSPICIOUS_FILE_PATTERNS:
            if pattern.lower() in cmdline or pattern.lower() in path:
                return DetectionResult(
                    confidence=self.confidence,
                    severity=self.severity,
                    mitre_id=self.mitre_id,
                    evidence=[f"Accessed credential file: {pattern}"],
                    recommendation="Review if this access is legitimate",
                )

        return None
