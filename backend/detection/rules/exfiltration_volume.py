"""Rule - Exfiltration over the C2 channel (MITRE T1041).

Flags per-process HTTP/S transfer volumes that are anomalous for an
endpoint: many megabytes of upload/download or very high request counts
from a single process within a short window.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import HttpRequest
from backend.detection.rules.base import BaseRule, DetectionResult

BYTES_THRESHOLD = 5_000_000  # 5 MB per process per window
COUNT_THRESHOLD = 250  # 250 requests per process per window


class ExfiltrationVolumeRule(BaseRule):
    rule_id = "exfiltration_volume"
    name = "Bulk Data Exfiltration"
    description = (
        "A single process transferred an anomalous volume of HTTP/S data "
        "within the detection window - consistent with exfiltration over the "
        "command-and-control channel."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1041"
    recommendation = (
        "Block the destination host, inspect the process memory and parent "
        "chain, determine which data left the host and notify incident response."
    )

    def __init__(
        self,
        session,
        bytes_threshold: int = BYTES_THRESHOLD,
        count_threshold: int = COUNT_THRESHOLD,
    ):
        super().__init__(session)
        self.bytes_threshold = bytes_threshold
        self.count_threshold = count_threshold

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        rows = self.session.scalars(
            select(HttpRequest).where(
                HttpRequest.observed_at >= since,
                *self._org_conds(HttpRequest),
            )
        ).all()

        totals: dict[str, dict] = defaultdict(lambda: {"bytes": 0, "count": 0})
        for req in rows:
            process = (req.process or "?").strip() or "?"
            totals[process]["bytes"] += (req.request_body_size or 0) + (
                req.response_body_size or 0
            )
            totals[process]["count"] += 1

        for process, stats in totals.items():
            over_bytes = stats["bytes"] >= self.bytes_threshold
            over_count = stats["count"] >= self.count_threshold
            if not (over_bytes or over_count):
                continue

            reasons = []
            if over_bytes:
                reasons.append(f"{stats['bytes']:,} bytes transferred")
            if over_count:
                reasons.append(f"{stats['count']} requests")

            confidence = min(
                0.95, self.confidence + (0.05 if over_bytes and over_count else 0.0)
            )
            findings.append(
                self._result(
                    evidence=(
                        f"Process '{process}' transferred {', '.join(reasons)} "
                        f"within {window_minutes} minutes - possible data exfiltration."
                    ),
                    event_ids=[],
                    confidence=confidence,
                )
            )
        return findings
