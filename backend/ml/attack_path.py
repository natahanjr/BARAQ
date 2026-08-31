"""Attack path prediction — predictive modeling using entity graph.

Given a set of compromised entities, predict the most likely next steps
an attacker would take based on MITRE ATT&CK technique transitions and
historical alert patterns.
"""
import logging
from collections import defaultdict
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("baraq.attack_path")


class AttackStep(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    probability: float
    from_entity: str = ""
    to_entity: str = ""
    evidence: str = ""


class AttackPath(BaseModel):
    path_id: str
    steps: list[AttackStep]
    risk_score: float
    entry_point: str
    predicted_target: str
    confidence: float


class AttackPathPredictor:
    """Predict likely attack paths from current compromise state."""

    TRANSITION_MATRIX = {
        ("initial-access", "execution"): 0.85,
        ("execution", "persistence"): 0.70,
        ("execution", "privilege-escalation"): 0.75,
        ("persistence", "privilege-escalation"): 0.65,
        ("privilege-escalation", "defense-evasion"): 0.80,
        ("defense-evasion", "credential-access"): 0.70,
        ("credential-access", "lateral-movement"): 0.85,
        ("lateral-movement", "collection"): 0.60,
        ("collection", "exfiltration"): 0.75,
        ("exfiltration", "impact"): 0.80,
        ("lateral-movement", "discovery"): 0.55,
        ("discovery", "collection"): 0.50,
        ("persistence", "collection"): 0.45,
        ("credential-access", "discovery"): 0.50,
    }

    TECHNIQUE_BY_TACTIC = {
        "execution": [
            ("T1059", "Command and Scripting Interpreter"),
            ("T1204", "User Execution"),
            ("T1047", "Windows Management Instrumentation"),
        ],
        "persistence": [
            ("T1053", "Scheduled Task/Job"),
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1136", "Create Account"),
        ],
        "privilege-escalation": [
            ("T1078", "Valid Accounts"),
            ("T1548", "Abuse Elevation Control Mechanism"),
        ],
        "defense-evasion": [
            ("T1027", "Obfuscated Files or Information"),
            ("T1070", "Indicator Removal on Host"),
        ],
        "credential-access": [
            ("T1003", "OS Credential Dumping"),
            ("T1110", "Brute Force"),
        ],
        "lateral-movement": [
            ("T1021", "Remote Services"),
            ("T1570", "Lateral Tool Transfer"),
        ],
        "collection": [
            ("T1005", "Data from Local System"),
            ("T1039", "Data from Network Shared Drive"),
        ],
        "exfiltration": [
            ("T1041", "Exfiltration Over C2 Channel"),
            ("T1567", "Exfiltration Over Web Service"),
        ],
        "discovery": [
            ("T1087", "Account Discovery"),
            ("T1082", "System Information Discovery"),
        ],
        "impact": [
            ("T1486", "Data Encrypted for Impact"),
            ("T1489", "Service Stop"),
        ],
    }

    def __init__(self, historical_alerts: Optional[list[dict]] = None):
        self._historical = historical_alerts or []
        self._transition_counts: dict[tuple, int] = defaultdict(int)
        self._build_transition_counts()

    def _build_transition_counts(self):
        for alert in self._historical:
            tactic = alert.get("mitre_tactic", "")
            next_tactic = alert.get("next_mitre_tactic", "")
            if tactic and next_tactic:
                self._transition_counts[(tactic, next_tactic)] += 1

    def _transition_probability(self, from_tactic: str, to_tactic: str) -> float:
        key = (from_tactic, to_tactic)
        if key in self.TRANSITION_MATRIX:
            return self.TRANSITION_MATRIX[key]
        total = sum(v for k, v in self._transition_counts.items() if k[0] == from_tactic)
        if total > 0:
            return self._transition_counts.get(key, 0) / total
        return 0.1

    def predict_next_steps(self, current_tactics: list[str], top_k: int = 3) -> list[AttackStep]:
        candidates: list[AttackStep] = []
        seen = set()
        for tactic in current_tactics:
            for (from_t, to_t), prob in self.TRANSITION_MATRIX.items():
                if from_t == tactic and to_t not in current_tactics and to_t not in seen:
                    seen.add(to_t)
                    techniques = self.TECHNIQUE_BY_TACTIC.get(to_t, [])
                    for tid, tname in techniques[:1]:
                        candidates.append(AttackStep(
                            technique_id=tid,
                            technique_name=tname,
                            tactic=to_t,
                            probability=prob,
                        ))
        candidates.sort(key=lambda s: s.probability, reverse=True)
        return candidates[:top_k]

    def build_attack_path(self, entry_tactic: str, compromised_tactics: list[str], path_id: str = "") -> AttackPath:
        all_tactics = list(compromised_tactics) + [entry_tactic]
        steps = self.predict_next_steps(all_tactics, top_k=5)
        risk_score = sum(s.probability for s in steps) / max(len(steps), 1) * 100
        return AttackPath(
            path_id=path_id or f"ap-{hash(tuple(all_tactics)) % 100000:05d}",
            steps=steps,
            risk_score=round(risk_score, 1),
            entry_point=entry_tactic,
            predicted_target=steps[0].tactic if steps else "unknown",
            confidence=steps[0].probability if steps else 0.0,
        )

    def analyze_blast_radius(self, compromised_entity: str, connected_entities: list[str]) -> dict:
        n = len(connected_entities)
        if n == 0:
            return {"entity": compromised_entity, "blast_radius": 0, "risk_level": "low"}
        risk = min(n / 20.0, 1.0)
        return {
            "entity": compromised_entity,
            "blast_radius": n,
            "connected_entities": connected_entities,
            "risk_level": "critical" if risk > 0.8 else "high" if risk > 0.5 else "medium" if risk > 0.2 else "low",
            "risk_score": round(risk * 100, 1),
        }
