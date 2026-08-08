"""Rule 1 - Brute Force Detection (MITRE T1110, Credential Access).

Multiple failed logons (4625) against the same account within a short
time interval, typically from a single source address.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import String, func, select

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

    def __init__(self, session, threshold: int = 5, window_minutes: int = 10,
                 spray_distinct_ips: int = 7, min_spread_ips: int = 3):
        super().__init__(session)
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.spray_distinct_ips = spray_distinct_ips
        self.min_spread_ips = min_spread_ips

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
        return findings + self._distributed_spray(since, window_minutes)

    def _distributed_spray(self, since, window_minutes: int) -> list[DetectionResult]:
        """Distributed password spray: many failed logons for one account
        spread across many distinct source IPs (no single source crosses the
        per-source threshold). Grouping by user alone catches what the
        per-(user, source) branch above cannot.
        """
        stmt = (
            select(
                NormalizedEvent.user,
                func.count(NormalizedEvent.id).label("attempts"),
                func.count(func.distinct(
                    NormalizedEvent.raw_json["facts"]["source_ip"].cast(String)
                )).label("distinct_ips"),
                func.min(NormalizedEvent.timestamp).label("first_ts"),
                func.max(NormalizedEvent.timestamp).label("last_ts"),
            )
            .where(
                NormalizedEvent.event_id == 4625,
                NormalizedEvent.timestamp >= since,
            )
            .group_by(NormalizedEvent.user)
            .having(func.count(NormalizedEvent.id) >= self.threshold)
        )

        findings: list[DetectionResult] = []
        for row in self.session.execute(stmt).all():
            attempts = int(row.attempts)
            distinct_ips = int(row.distinct_ips)
            if distinct_ips >= self.spray_distinct_ips:
                tier = "spray"
            elif distinct_ips >= self.min_spread_ips and attempts >= self.threshold * 2:
                tier = "spread"
            else:
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
            if tier == "spray":
                evidence = (
                    f"{attempts} failed logons for account '{row.user}' across "
                    f"{distinct_ips} distinct source IPs between "
                    f"{row.first_ts.isoformat()} and {row.last_ts.isoformat()} "
                    f"({window_minutes} minute window) — distributed password spray."
                )
                findings.append(
                    self._result(
                        evidence=evidence,
                        event_ids=ev_ids,
                        severity=self.severity,
                        confidence=min(0.95, 0.75 + attempts * 0.01),
                    )
                )
            else:
                evidence = (
                    f"{attempts} failed logons for account '{row.user}' from "
                    f"{distinct_ips} moderately spread source IPs between "
                    f"{row.first_ts.isoformat()} and {row.last_ts.isoformat()} "
                    f"({window_minutes} minute window) — possible distributed brute force."
                )
                findings.append(
                    self._result(
                        evidence=evidence,
                        event_ids=ev_ids,
                        severity="medium",
                        confidence=min(0.85, 0.6 + attempts * 0.01),
                    )
                )
        return findings
