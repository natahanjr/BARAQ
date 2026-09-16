"""T1134 - Access Token Manipulation.

Detects token manipulation techniques: token impersonation,
token theft, and privilege escalation via token abuse.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

TOKEN_TECHNIQUES = [
    (r"adjusttokenprivileges", "Token privilege adjustment"),
    (r"ntadjusttokenprivileges", "NT token privilege adjustment"),
    (r"impersonateloggedonuser", "Impersonating logged-on user"),
    (r"createprocesswithlogonw", "Creating process with logon token"),
    (r"createprocessasuserw", "Creating process as another user"),
    (r"createprocessasusera", "Creating process as another user"),
    (r"setthreadtoken", "Setting thread token"),
    (r"droptokenprivilege", "Dropping token privilege"),
    (r"privilege::debug", "Enabling debug privilege"),
    (r"token::elevate", "Token elevation"),
    (r"token::elevate /domain", "Domain token elevation"),
    (r"token::list", "Token enumeration"),
    (r"token::revert", "Reverting token changes"),
    (r"psexec.*-s", "PsExec with SYSTEM token"),
    (r"psexec.*-i", "PsExec interactive session"),
    (r"runas /user:", "RunAs token impersonation"),
    (r"runas.exe.*\/user:", "RunAs token impersonation"),
    (r"make_token", "Make token for impersonation"),
    (r"invoke-kerberoast", "Kerberoasting for token theft"),
    (r"getsystem", "Metasploit getsystem token"),
    (r"incognito", "Incognito token impersonation"),
    (r"loadtoken", "Loading stolen token"),
    (r"rev2self", "Reverting to self from impersonation"),
    (r"steal_token", "Stealing process token"),
    (r"token窃取", "Token theft in Chinese"),
]

SUSPICIOUS_PARENTS = [
    "wmiprvse",
    "svchost",
    "services",
    "lsass",
    "csrss",
    "winlogon",
]


class TokenManipulationRule(BaseRule):
    rule_id = "BARAQ-PRIV-003"
    title = "Access Token Manipulation"
    description = "Detects token manipulation and impersonation techniques"
    mitre_id = "T1134"
    severity = "high"
    confidence = 0.80

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in TOKEN_TECHNIQUES:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        if not evidence:
            return None

        severity = "critical" if any("elevate" in e.lower() or "impersonat" in e.lower() for e in evidence) else self.severity

        return DetectionResult(
            confidence=min(0.95, self.confidence + 0.03 * len(evidence)),
            severity=severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="Investigate token manipulation for privilege escalation",
        )
