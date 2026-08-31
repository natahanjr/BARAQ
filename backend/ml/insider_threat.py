"""Insider threat detection — dedicated scoring and classification."""
import logging
from enum import Enum
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.insider_threat")


class ThreatLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InsiderThreatScore(BaseModel):
    username: str
    threat_level: ThreatLevel
    score: float
    indicators: list[str] = []
    recommended_actions: list[str] = []


class InsiderThreatDetector:
    RISK_WEIGHTS = {
        "off_hours_activity": 15,
        "data_staging": 25,
        "large_transfer": 25,
        "privilege_escalation": 35,
        "unusual_process": 20,
        "new_ip": 10,
        "mass_download": 20,
        "policy_violation": 15,
    }

    def __init__(self):
        self._scores: dict[str, InsiderThreatScore] = {}

    def evaluate(self, username: str, indicators: list[str]) -> InsiderThreatScore:
        score = 0.0
        for ind in indicators:
            score += self.RISK_WEIGHTS.get(ind, 5)
        score = min(score, 100.0)
        if score >= 80:
            level = ThreatLevel.CRITICAL
        elif score >= 60:
            level = ThreatLevel.HIGH
        elif score >= 40:
            level = ThreatLevel.MEDIUM
        elif score >= 20:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.NONE
        actions = []
        if level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            actions.append("Disable account immediately")
            actions.append("Notify security team")
            actions.append("Preserve evidence")
        if level == ThreatLevel.MEDIUM:
            actions.append("Increase monitoring")
            actions.append("Review recent activity")
        result = InsiderThreatScore(
            username=username, threat_level=level, score=score,
            indicators=indicators, recommended_actions=actions,
        )
        self._scores[username] = result
        return result

    def get_score(self, username: str) -> Optional[InsiderThreatScore]:
        return self._scores.get(username)

    def list_high_risk(self) -> list[InsiderThreatScore]:
        return [s for s in self._scores.values() if s.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)]
