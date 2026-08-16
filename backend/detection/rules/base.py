"""Base detection rule contract."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.models import NormalizedEvent, ProcessRecord


class DetectionResult:
    """Outcome of one rule evaluation."""

    __slots__ = (
        "rule",
        "name",
        "description",
        "severity",
        "confidence",
        "evidence",
        "event_ids",
        "mitre_id",
        "recommendation",
        "correlation_id",
    )

    def __init__(
        self,
        rule: str,
        name: str,
        description: str,
        severity: str,
        confidence: float,
        evidence: str,
        event_ids: list[int],
        mitre_id: str = "T0000",
        recommendation: str = "",
        correlation_id: str = "",
    ):
        self.rule = rule
        self.name = name
        self.description = description
        self.severity = severity
        self.confidence = confidence
        self.evidence = evidence
        self.event_ids = event_ids
        self.mitre_id = mitre_id
        self.recommendation = recommendation
        self.correlation_id = correlation_id

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "event_ids": self.event_ids,
            "mitre_id": self.mitre_id,
            "recommendation": self.recommendation,
            "correlation_id": self.correlation_id,
        }


class BaseRule(ABC):
    """Every detection rule:

    * declares which MITRE technique(s) it maps to,
    * receives the DB session and the detection window,
    * returns zero or more DetectionResult objects.
    """

    rule_id: str = "rule"
    name: str = "Unnamed rule"
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.6
    mitre_id: str = "T0000"
    recommendation: str = "Investigate the evidence."

    def __init__(self, session: Session, org: str | None = None):
        self.session = session
        # Tenant scope: None = evaluate across all orgs (legacy/direct use),
        # "" or a named org limits every query of this rule to that tenant.
        self.org = org
        self.logger = logging.getLogger(f"baraq.rules.{self.rule_id}")

    def _org_conds(self, model):
        """Extra WHERE conditions restricting a query to this rule's tenant.

        Returns ``()`` when the rule is unscoped (``org is None``), or the
        org equality expression otherwise - safe to unpack into ``where()``.
        """
        if self.org is None:
            return ()
        return (model.org == self.org,)

    @abstractmethod
    def evaluate(self, window_minutes: int, since_id: int | None = None) -> list[DetectionResult]:
        """Evaluate the rule against events in the DB and return findings.

        ``since_id`` (optional) is the incremental-detection cursor: rules
        that support it only examine events with ``id > since_id``. Rules
        that need window history (aggregations, cross-event correlation)
        ignore it and keep evaluating the full window; the engine only
        passes it to rules that declare the parameter.
        """

    def _result(self, evidence: str, event_ids: list[int], **overrides) -> DetectionResult:
        return DetectionResult(
            rule=overrides.get("rule", self.rule_id),
            name=overrides.get("name", self.name),
            description=overrides.get("description", self.description),
            severity=overrides.get("severity", self.severity),
            confidence=overrides.get("confidence", self.confidence),
            evidence=evidence,
            event_ids=event_ids,
            mitre_id=overrides.get("mitre_id", self.mitre_id),
            recommendation=overrides.get("recommendation", self.recommendation),
        )

    def cmdline_candidates(self, since: datetime) -> list[tuple[str, str, str]]:
        """Yield (command_line, source_label, user) from process snapshots and
        normalized 4688/4104 events so command-line rules share one source."""
        out: list[tuple[str, str, str]] = []
        for pr in self.session.scalars(
            select(ProcessRecord).where(
                ProcessRecord.observed_at >= since,
                *self._org_conds(ProcessRecord),
                ProcessRecord.command_line.isnot(None),
                ProcessRecord.command_line != "",
            )
        ).all():
            out.append((pr.command_line, f"pid {pr.pid} ({pr.name})", pr.user))
        for ev in self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.event_id.in_([4688, 4104]),
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all():
            facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
            cl = facts.get("command_line") or facts.get("cmdline") or ""
            if cl:
                out.append((cl, f"Event {ev.event_id} (user '{ev.user}')", ev.user))
        return out
