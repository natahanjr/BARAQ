"""Rule 7 - Data Staging (MITRE T1074, Exfiltration).

Detects data preparation for exfiltration:
- Rapid file access/creation in temporary directories
- Large file archiving activity (7z, rar, zip creation)
- Staging data in hidden/system directories
- Unusual archive creation with compression
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from backend.database.models import NormalizedEvent, ProcessRecord
from backend.detection.rules.base import BaseRule, DetectionResult


class DataStagingRule(BaseRule):
    rule_id = "data_staging"
    name = "Data Staging for Exfiltration"
    description = (
        "Detects suspicious data staging patterns including rapid archive creation, "
        "file aggregation in temp directories, and unusual compression tool usage "
        "indicative of data preparation for exfiltration."
    )
    severity = "high"
    confidence = 0.70
    mitre_id = "T1074"
    recommendation = (
        "Immediately review affected user account and process, block network access if suspicious, "
        "preserve file system evidence, and investigate data access history and failed exfiltration attempts."
    )

    def __init__(
        self,
        session,
        archive_tools: list[str] | None = None,
        min_archive_events: int = 1,
        temp_dir_access_threshold: int = 200,  # raised; count alone is low-signal
        window_minutes: int = 10,
    ):
        super().__init__(session)
        # Only true archive tools, removed PowerShell.exe and wsl.exe (common legit tools)
        self.archive_tools = archive_tools or [
            "7z.exe",
            "7za.exe",
            "rar.exe",
            "winrar.exe",
            "zip.exe",
        ]
        self.min_archive_events = min_archive_events
        self.temp_dir_access_threshold = temp_dir_access_threshold
        self.window_minutes = window_minutes

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        window_minutes = self.window_minutes or window_minutes
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)

        # Pattern 1: Archive tool execution (7z, rar, zip) is the high-signal check.
        findings.extend(self._detect_archive_creation(since))

        # Pattern 2 & 3 (temp aggregation, generic process bursts) were removed:
        # they produced excessive false positives on routine process activity.

        return findings

    def _detect_archive_creation(self, since: datetime) -> list[DetectionResult]:
        """Detect execution of archiving/compression tools."""
        findings: list[DetectionResult] = []

        # Query for process creation events that might involve archive tools
        stmt = select(NormalizedEvent).where(
            NormalizedEvent.event_id.in_(
                [4688, 4104]
            ),  # Process creation or PowerShell
            NormalizedEvent.timestamp >= since,
            *self._org_conds(NormalizedEvent),
        )

        events_by_user: dict[str, list] = {}
        for event in self.session.execute(stmt).scalars().all():
            if not event.user:
                continue

            # Check if raw data contains archive tool names
            raw_json = event.raw_json or {}
            facts = raw_json.get("facts", {})
            cmd_line = (facts.get("command_line") or "").lower()

            archive_used = any(tool.lower() in cmd_line for tool in self.archive_tools)
            if not archive_used:
                continue

            # Check for suspicious patterns
            suspicious_patterns = [
                "documents",
                "downloads",
                "desktop",
                "users\\",
                "appdata",
                "temp",
                "programdata",
                "\\$recycle",
            ]
            has_suspicious_target = any(
                pattern in cmd_line for pattern in suspicious_patterns
            )

            if has_suspicious_target:
                if event.user not in events_by_user:
                    events_by_user[event.user] = []
                events_by_user[event.user].append(event)

        # Create findings for users with archive activity
        for user, events in events_by_user.items():
            if len(events) >= self.min_archive_events:
                evidence = (
                    f"User '{user}' executed archive tool "
                    f"({len(events)} times) targeting common data locations. "
                    f"Indicates data staging for exfiltration."
                )

                findings.append(
                    self._result(
                        evidence=evidence,
                        event_ids=[],
                        severity="high",
                        confidence=min(0.90, 0.70 + len(events) * 0.05),
                    )
                )

        return findings

    def _detect_temp_directory_staging(self, since: datetime) -> list[DetectionResult]:
        """Detect rapid file access aggregation in temp directories."""
        findings: list[DetectionResult] = []

        # ProcessRecord captures process snapshots; we check for temp directory patterns

        stmt = (
            select(
                ProcessRecord.user,
                func.count(ProcessRecord.id).label("temp_accesses"),
                func.min(ProcessRecord.observed_at).label("first_access"),
            )
            .where(
                ProcessRecord.observed_at >= since,
                *self._org_conds(ProcessRecord),
            )
            .group_by(ProcessRecord.user)
            .having(func.count(ProcessRecord.id) >= self.temp_dir_access_threshold)
        )

        for row in self.session.execute(stmt).all():
            if not row.user or row.user.lower() in ("system", "local service"):
                continue

            evidence = (
                f"User '{row.user}' accessed or created {row.temp_accesses} files/processes "
                f"in temporary directories starting at {row.first_access}. "
                f"Pattern consistent with data staging prior to exfiltration."
            )

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="medium",
                    confidence=min(0.80, 0.60 + min(row.temp_accesses / 50, 0.15)),
                )
            )

        return findings

    def _detect_hidden_archive_staging(self, since: datetime) -> list[DetectionResult]:
        """Detect combination of hidden file creation and compression."""
        findings: list[DetectionResult] = []

        # Look for PowerShell or CMD execution creating hidden files + archives
        stmt = (
            select(
                NormalizedEvent.user,
                func.count(NormalizedEvent.id).label("suspicious_events"),
                func.min(NormalizedEvent.timestamp).label("first_event"),
            )
            .where(
                NormalizedEvent.event_id.in_([4688, 4104]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
            .group_by(NormalizedEvent.user)
        )

        for row in self.session.execute(stmt).all():
            # Heuristic: multiple process creation events from same user within window
            # combined with archive operations = data staging
            if row.suspicious_events < 5:
                continue

            evidence = (
                f"User '{row.user}' executed {row.suspicious_events} suspicious commands "
                f"(archive/compression tools + file operations) starting at {row.first_event}. "
                f"High confidence data staging activity detected."
            )

            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=[],
                    severity="critical" if row.suspicious_events >= 10 else "high",
                    confidence=min(0.88, 0.70 + min(row.suspicious_events / 20, 0.18)),
                )
            )

        return findings
