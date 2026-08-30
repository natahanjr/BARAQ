"""Rule - Credentials from Password Stores (MITRE T1555).

Flags commands that enumerate or export the Windows Credential Manager
(cmdkey /list, vaultcmd), open the Credential Manager control panel
(rundll32 keymgr.dll), extract DPAPI master keys (mimikatz dpapi, crypt
Unprotect), or read browser credential stores (Login Data, cookies,
logins.json) - each a signal of credential-store theft.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_CRED_STORE = re.compile(
    r"cmdkey(?:\.exe)?\s+/list\b|"
    r"vaultcmd(?:\.exe)?\b|"
    r"rundll32(?:\.exe)?\b[^\n]*keymgr(?:\.dll)?\b|"
    r"keymgr\.dll\b|"
    r"[\\/]Microsoft[\\/]Credentials\b|"
    r"[\\/]Roaming[\\/]Microsoft[\\/]Vault\b|"
    r"(?:mimikatz|sekurlsa:?)\b[^\n]*(?:dpapi|kerberos|vault)\b|"
    r"dpapi\.(?:master|cache|crpfx)|"
    r"Get-StoredCredential\b",
    re.IGNORECASE,
)

_BROWSER_CRED = re.compile(
    r"(?:login data|cookies\.db|logins\.json|web data|key[^\\\s]*\.sqlite3?)"
    r"\b[^\n]*(?:\\AppData\\|\\users\\|\\Program Files)|"
    r"\b[^\n]*\\Chrome\\User Data\\\w+\\(?:Login Data|cookies)|"
    r"\b[^\n]*\\Firefox\\Profiles\\\w+\\.*(?:logins|key4)",
    re.IGNORECASE,
)


class CredentialStoreTheftRule(BaseRule):
    rule_id = "credential_store_theft"
    name = "Credentials from Password Stores"
    description = (
        "A command enumerated or exported credentials from the Windows "
        "Credential Manager, DPAPI-protected stores or browser credential "
        "databases - classic credential-store theft (T1555)."
    )
    severity = "critical"
    confidence = 0.8
    mitre_id = "T1555"
    recommendation = (
        "Rotate all credentials reachable from the affected profile, enable "
        "Credential Guard and DPAPI user protection, inspect the parent "
        "process chain, and hunt for lateral movement with the exposed "
        "credentials."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            match = _CRED_STORE.search(cmdline) or _BROWSER_CRED.search(cmdline)
            if not match:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Credential-store access by '{user}' ({label}): "
                        f"{cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
