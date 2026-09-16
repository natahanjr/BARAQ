"""T1486 - Data Encrypted for Impact (Ransomware).

Detects ransomware behavior: bulk file encryption, ransom note
creation, file extension changes, and volume shadow copy deletion.
"""

from __future__ import annotations

import re

from backend.detection.rules.base import BaseRule, DetectionResult

RANSOMWARE_INDICATORS = [
    (r"vssadmin\s+delete\s+shadows\s+\/all", "Volume shadow copy deletion"),
    (r"vssadmin\.exe\s+delete\s+shadows", "Volume shadow copy deletion"),
    (r"wmic\s+shadowcopy\s+delete", "WMI shadow copy deletion"),
    (r"bcdedit\s+\/set\s+{default}\s+recoveryenabled\s+no", "Disabling Windows recovery"),
    (r"bcdedit\s+\/set\s+{default}\s+bootstatuspolicy\s+ignoreallfailures", "Ignoring boot failures"),
    (r"bcdedit\s+\/set\s+{current}\s+recoveryenabled\s+no", "Disabling current recovery"),
    (r"cipher\s+\/w:", "Wiping free space"),
    (r"wevtutil\s+cl\s+security", "Clearing security event log"),
    (r"wevtutil\s+cl\s+system", "Clearing system event log"),
    (r"wevtutil\s+cl\s+application", "Clearing application event log"),
    (r"del\s+\/s\s+\/q\s+\*\.doc", "Bulk document deletion"),
    (r"del\s+\/s\s+\/q\s+\*\.pdf", "Bulk PDF deletion"),
    (r"del\s+\/s\s+\/q\s+\*\.jpg", "Bulk image deletion"),
    (r"del\s+\/s\s+\/q\s+\*\.xlsx", "Bulk Excel deletion"),
    (r"ren\s+\*\.\w+\s+\*\.locked", "Bulk file renaming to .locked"),
    (r"ren\s+\*\.\w+\s+\*\.encrypted", "Bulk file renaming to .encrypted"),
    (r"ren\s+\*\.\w+\s+\*\.crypto", "Bulk file renaming to .crypto"),
    (r"ren\s+\*\.\w+\s+\*\.cerber", "Bulk file renaming to .cerber"),
    (r"ren\s+\*\.\w+\s+\*\.wannacry", "Bulk file renaming to .wannacry"),
    (r"ren\s+\*\.\w+\s+\*\.ryuk", "Bulk file renaming to .ryuk"),
    (r"ren\s+\*\.\w+\s+\*\.lockbit", "Bulk file renaming to .lockbit"),
    (r"ren\s+\*\.\w+\s+\*\.conti", "Bulk file renaming to .conti"),
    (r"ren\s+\*\.\w+\s+\*\.revil", "Bulk file renaming to .revil"),
    (r"ren\s+\*\.\w+\s+\*\.maze", "Bulk file renaming to .maze"),
    (r"ren\s+\*\.\w+\s+\*\.darkside", "Bulk file renaming to .darkside"),
    (r"ren\s+\*\.\w+\s+\*\.avaddon", "Bulk file renaming to .avaddon"),
    (r"ren\s+\*\.\w+\s+\*\. الكوي", "Bulk file renaming to .kyva"),
    (r"fsutil\s+file\s+seteof", "Setting file end-of-file (encryption marker)"),
    (r"icacls\s+\/grant\s+everyone:F", "Granting full access to all files"),
    (r"takeown\s+\/f.*\/r", "Taking ownership of all files recursively"),
]

RANSOM_NOTE_PATTERNS = [
    "readme.txt",
    "readme.html",
    "how_to_decrypt",
    "how_to_recover",
    "decrypt_instructions",
    "restore_files",
    "your_files_are_encrypted",
    "important.txt",
    "help_decrypt",
    "contact_us",
    "bitcoin",
    "wallet",
    "onion",
    "tor",
    "pay_ransom",
    "ransomware",
]


class RansomwareRule(BaseRule):
    rule_id = "BARAQ-IMPACT-001"
    title = "Ransomware Activity Detected"
    description = "Detects ransomware behavior including encryption, shadow copy deletion, and ransom notes"
    mitre_id = "T1486"
    severity = "critical"
    confidence = 0.90

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        path = (event.get("path") or "").lower()
        if not cmdline:
            return None

        evidence = []

        for pattern, desc in RANSOMWARE_INDICATORS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                evidence.append(desc)

        for note in RANSOM_NOTE_PATTERNS:
            if note in cmdline or note in path:
                evidence.append(f"Ransom note indicator: {note}")

        if not evidence:
            return None

        return DetectionResult(
            confidence=min(0.99, self.confidence + 0.01 * len(evidence)),
            severity=self.severity,
            mitre_id=self.mitre_id,
            evidence=evidence[:5],
            recommendation="CRITICAL: Ransomware activity. Isolate host and initiate incident response.",
        )
