"""Rule 4 - Persistence Detection (MITRE T1547, Persistence).

Detects startup persistence mechanisms: new services (7045), new
scheduled tasks (4698) and suspicious binary paths in unusual
directories (temp, public, appdata).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_DIRS = re.compile(
    r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Windows\\Tasks\\|\\ProgramData\\",
    re.IGNORECASE,
)
SUSPICIOUS_BINS = re.compile(r"\.(exe|dll|ps1|vbs|bat|cmd|scr)$", re.IGNORECASE)


def _path_flags(path: str) -> tuple[bool, bool]:
    suspicious_dir = bool(SUSPICIOUS_DIRS.search(path))
    suspicious_bin = bool(SUSPICIOUS_BINS.search(path)) and not path.lower().endswith(
        ".dll"
    )
    return suspicious_dir, suspicious_bin


class PersistenceRule(BaseRule):
    rule_id = "persistence"
    name = "Persistence Mechanism Installed"
    description = (
        "A new service or scheduled task was created with a binary path "
        "located in a suspicious directory, a common persistence technique."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1547"
    recommendation = (
        "Remove the persistence entry, terminate the associated process, "
        "scan the host for additional backdoors and review startup locations."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([7045, 4698, 4702]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for event in rows:
            facts = (event.raw_json or {}).get("facts", {}) if event.raw_json else {}
            path = facts.get("image_path") or facts.get("service_file") or ""
            name = facts.get("service_name") or facts.get("task_name") or "unknown"
            if not path:
                continue

            dir_flag, bin_flag = _path_flags(path)
            if not dir_flag:
                continue

            # Common masquerading names (legit-looking, non-standard service).
            masquerade = re.fullmatch(
                r"(Windows[A-Za-z]+(?:Svc|Service|Update|Task)|System[A-Za-z]+)", name
            )
            confidence = (
                self.confidence
                + (0.1 if masquerade else 0.0)
                + (0.05 if bin_flag else 0.0)
            )

            evidence = (
                f"{'Service' if event.event_id == 7045 else 'Scheduled task'} "
                f"'{name}' (Event {event.event_id}) created by '{event.user}' with "
                f"binary path '{path}' located in a suspicious directory."
            )
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[event.id],
                    confidence=min(0.95, confidence),
                )
            )
        return findings
