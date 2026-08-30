"""Rule - Shortcut Modification for persistence (MITRE T1547.009).

Flags creation or modification of .lnk shortcut files inside the user or
global Startup folders (and similar autostart locations), especially when
the shortcut is built from a script (WScript.Shell CreateShortcut) with an
executable target - a lightweight, commonly missed persistence vector.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_STARTUP_FOLDER = re.compile(
    r"start\s*menu[\\/]programs[\\/]startup\b|"
    r"[\\/]startup(?:[\\/]|\b)|"
    r"(?:programdata|appdata)[\\/]roaming[\\/]microsoft"
    r"[\\/]windows[\\/]start\s*menu[\\/]programs[\\/]startup",
    re.IGNORECASE,
)

_LNK_CREATE = re.compile(
    r"\.lnk\b|"
    r"CreateShortcut\b|"
    r"\b(?:wscript|powershell|cmd)\.exe\b[^\n]*(?:\.lnk|CreateShortcut|shortcut)",
    re.IGNORECASE,
)

_EXEC_TARGET = re.compile(
    r"(?:targetpath|\.TargetPath|/t[^\s]*)\s*[=:]\s*[\"']?[^\s\"']+\.(?:exe|bat|cmd|com|ps1|vbs|js)\b",
    re.IGNORECASE,
)


class ShortcutModificationRule(BaseRule):
    rule_id = "shortcut_modification"
    name = "Startup Shortcut Modified"
    description = (
        "A command created or modified a .lnk shortcut in a Startup folder, "
        "optionally pointing at an executable target - a persistence "
        "mechanism that runs the payload at logon (T1547.009)."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1547.009"
    recommendation = (
        "Remove the shortcut and its target, scan the Startup folder for "
        "sibling implants, and restrict write access to autostart locations."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not (_LNK_CREATE.search(cmdline) and _STARTUP_FOLDER.search(cmdline)):
                continue
            indicators = []
            if _EXEC_TARGET.search(cmdline):
                indicators.append("shortcut target is an executable")
            if "CreateShortcut" in cmdline:
                indicators.append("shortcut created from a script")
            findings.append(
                self._result(
                    evidence=(
                        f"Startup-folder shortcut created/modified by '{user}' "
                        f"({label}): {'; '.join(indicators) or 'shortcut created'}. "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
