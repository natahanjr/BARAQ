"""Rule - Registry Run Keys / Startup persistence (MITRE T1547.001).

Flags Sysmon Event 13 (Registry Value Set / Key Create) operations that
write to autostart keys (Run, RunOnce, RunServices, StartupApproved).
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

# Substrings of TargetObject that indicate an autostart key was written.
RUN_KEY_HINTS = (
    r"\\CurrentVersion\\Run(?:Once)?\\",
    r"\\CurrentVersion\\RunServices(?:Once)?\\",
    r"\\Policies\\Explorer\\Run\\",
    r"\\CurrentVersion\\StartupApproved\\",
)
_RUN_KEY = re.compile("|".join(RUN_KEY_HINTS), re.IGNORECASE)

SUSPICIOUS_DIRS = re.compile(r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\", re.IGNORECASE)


class RegistryRunKeyRule(BaseRule):
    rule_id = "registry_run_key"
    name = "Persistent Run Key Installed"
    description = (
        "A registry autostart key (Run / RunOnce) was created or modified so "
        "that an attacker-controlled binary executes at logon."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1547.001"
    recommendation = (
        "Remove the registry value, delete the dropped binary, review the "
        "writing process and scan for additional persistence mechanisms."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id == 13,
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            target = facts.get("target_object") or ""
            if not _RUN_KEY.search(target):
                continue

            image = facts.get("image") or "?"
            details = facts.get("details") or "<value deleted>"
            suspicious_image = bool(SUSPICIOUS_DIRS.search(str(image)))
            confidence = min(0.95, self.confidence + (0.1 if suspicious_image else 0.0))

            findings.append(
                self._result(
                    evidence=(
                        f"Registry {facts.get('event_type', 'SetValue')} on autostart key "
                        f"'{target}' = '{details}' by '{image}' as '{event.user}'."
                    ),
                    event_ids=[event.id],
                    confidence=confidence,
                )
            )
        return findings