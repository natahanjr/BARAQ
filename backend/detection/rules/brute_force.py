"""Rule 1 - Brute Force Detection (MITRE T1110, Credential Access).

Multiple failed logons (4625) against the same account within a short
time interval, typically from a single source address.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult


class BruteForceRule(BaseRule):
    rule_id = "brute_force"
    name = "Brute Force Attack"
    description = (
        "Multiple failed login attempts detected against the same account "
        "within a short time interval, suggesting credential brute-forcing."
    )
    severity = "high"
    confidence = 0.85
    mitre_id = "T1110"
    recommendation = (
        "Block the offending source IP, enforce account lockout thresholds, "
        "enable multi-factor authentication and reset the targeted account's password."
    )

    def __init__(self, session, threshold: int = 5, window_minutes: int = 10):
        super().__init__(session)
        self.threshold = threshold
        self.window_minutes = window_minutes

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        stmt = (
            select(
                NormalizedEvent.user,
                NormalizedEvent.raw_json,
                func.count(NormalizedEvent.id).label("attempts"),
                func.min(NormalizedEvent.timestamp).label("first_ts"),
                func.max(NormalizedEvent.timestamp).label("last_ts"),
            )
            .where(
                NormalizedEvent.event_id == 4625,
                NormalizedEvent.timestamp >= since,
            )
            .group_by(NormalizedEvent.user, NormalizedEvent.raw_json)
            .order_by(func.count(NormalizedEvent.id).desc())
        )

        findings: list[DetectionResult] = []
        for row in self.session.execute(stmt).all():
            attempts = int(row.attempts)
            if attempts < self.threshold:
                continue
            raw = row.raw_json or {}
            facts = raw.get("facts", {})
            source_ip = facts.get("source_ip", "unknown")
            if not source_ip or source_ip in ("-", "::1", "127.0.0.1"):
                continue

            ev_ids = list(
                self.session.scalars(
                    select(NormalizedEvent.id)
                    .where(
                        NormalizedEvent.event_id == 4625,
                        NormalizedEvent.user == row.user,
                        NormalizedEvent.timestamp >= since,
                    )
                )
            )

            evidence = (
                f"{attempts} failed logons for account '{row.user}' from "
                f"{source_ip} between {row.first_ts.isoformat()} and {row.last_ts.isoformat()} "
                f"({window_minutes} minute window)."
            )
            confidence = min(0.99, 0.7 + attempts * 0.02)
            findings.append(
                self._result(
                    evidence=evidence,
                    event_ids=ev_ids,
                    severity=self.severity if attempts >= 10 else "medium",
                    confidence=confidence,
                )
            )
        return findings
