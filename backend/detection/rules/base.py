"""Base detection rule contract."""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from sqlalchemy.orm import Session


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

    def __init__(self, session: Session):
        self.session = session
        self.logger = logging.getLogger(f"sentinel.rules.{self.rule_id}")

    @abstractmethod
    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        """Evaluate the rule against events in the DB and return findings."""

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
