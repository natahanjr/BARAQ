"""Rule - Impact techniques: ransomware / data encryption (T1486) and
inhibition of system recovery (T1490).

T1486 flags command lines that bulk-rename or re-encrypt user files with
ransomware-style extensions and drop ransom notes. T1490 flags deletion of
Volume Shadow Copies and boot-recovery tampering that precede destructive
encryption.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

#: Ransomware-style double extensions: e.g. report.pdf.locked, backup.zip.crypt
_RANSOM_EXT = re.compile(
    r"\.[A-Za-z0-9]{2,6}\.(?:locked|locky|crypt|crypted|encrypted|enc|zzz|wanna|rapid|"
    r"zepto|cerber|paym|dnh|alute|leox|crypto|aes|lock|mamba|ecc)$",
    re.IGNORECASE,
)

#: Bulk rename / re-encode of many files (cmd ren *..., PowerShell Rename-Item).
_BULK_RENAME = re.compile(
    r"\b(?:cmd(?:\.exe)?(?: /c)?\s+)?(?:ren|rename)\b[^\n]*\*\.[A-Za-z0-9*]+|"
    r"\bRename-Item\b[^\n]*\*\.\*|"
    r"\b(?:ren|rename)\b[^\n]*\*\.[A-Za-z0-9]+\.[A-Za-z0-9]+",
    re.IGNORECASE,
)

#: Ransom notes commonly dropped to the desktop / drive roots.
_RANSOM_NOTE = re.compile(
    r"(?i)(?:how[_-]?to[_-]?(?:decrypt|unlock)|read_?me|decrypt|unlock|restore|recover)"
    r"(?=[^\n]*(?:\.txt|\.hta|\.html|\.url)\b)"
)

#: Mass-repacking of documents/archives (7z a -r with many sources).
_COMPRESSION_REPACK = re.compile(
    r"\b(?:7z|rar|zip)(?:\.exe)?\b[^\n]*\b(?:a|m)\b[^\n]*\*\.(?:docx?|xlsx?|pdf|jpe?g|png|txt)",
    re.IGNORECASE,
)

_RECOVERY_KILL = re.compile(
    r"vssadmin(?:\.exe)?\s+delete\s+shadows?(?:\s+/quiet)?|"
    r"wmic(?:\.exe)?\b[^\n]*shadowcopy\b[^\n]*\bdelete\b|"
    r"bcdedit(?:\.exe)?\s+/set\b[^\n]*\brecoveryenabled\s+(?:no|off)|"
    r"bcdedit(?:\.exe)?\s+/set\b[^\n]*\bbootstatuspolicy\s+ignoreallfailures|"
    r"diskshadow(?:\.exe)?\b[^\n]*\bdelete\b|"
    r"wevtutil(?:\.exe)?\s+cl\b[^\n]*\.evtx\b",
    re.IGNORECASE,
)


class RansomwareImpactRule(BaseRule):
    rule_id = "ransomware_impact"
    name = "Data Encrypted for Impact (Ransomware)"
    description = (
        "Command lines showing bulk file renaming with ransomware extensions, "
        "mass-repacking of documents/archives, or ransom-note drops - the "
        "telltale signs of an in-progress encryption attack."
    )
    severity = "critical"
    confidence = 0.8
    mitre_id = "T1486"
    recommendation = (
        "Isolate the host and attached volumes immediately, preserve forensics "
        "offline, restore from immutable/air-gapped backups, and hunt for the "
        "initial access vector and the deployed encryption binary."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        for cmdline, label, user in self.cmdline_candidates(since):
            indicators = []
            if _RANSOM_EXT.search(cmdline):
                indicators.append("ransomware-style file extensions")
            if _BULK_RENAME.search(cmdline):
                indicators.append("bulk rename/re-encode of many files")
            if _RANSOM_NOTE.search(cmdline):
                indicators.append("ransom-note file creation")
            if _COMPRESSION_REPACK.search(cmdline):
                indicators.append("mass archive repacking")
            if not indicators:
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Potential ransomware activity by '{user}' ({label}): "
                        f"{'; '.join(indicators)}. Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class InhibitRecoveryRule(BaseRule):
    rule_id = "inhibit_recovery"
    name = "System Recovery Inhibited"
    description = (
        "A command deleted Volume Shadow Copies, disabled boot recovery or "
        "cleared backup state - a common precursor to a destructive "
        "ransomware deployment."
    )
    severity = "critical"
    confidence = 0.9
    mitre_id = "T1490"
    recommendation = (
        "Treat as an imminent destructive attack. Isolate the host, verify "
        "backup/shadow copy integrity on every other host, and initiate "
        "incident response."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _RECOVERY_KILL.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Recovery-inhibition command by '{user}' ({label}): "
                        f"{cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
