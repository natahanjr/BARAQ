"""MITRE ATT&CK gap analysis — automated report of detection coverage."""
import json
from pathlib import Path
from typing import Optional
from pydantic import BaseModel


class TechniqueCoverage(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    has_detection: bool
    detection_rules: list[str] = []
    alert_count: int = 0


class GapReport(BaseModel):
    total_techniques: int
    covered: int
    uncovered: int
    coverage_pct: float
    uncovered_techniques: list[TechniqueCoverage]
    covered_techniques: list[TechniqueCoverage]


TECHNIQUES_FILE = Path(__file__).parent / "techniques.json"


def load_techniques() -> list[dict]:
    if TECHNIQUES_FILE.exists():
        data = json.loads(TECHNIQUES_FILE.read_text())
        if isinstance(data, dict):
            return data.get("techniques", [])
        return data
    return []


def generate_gap_report(rules_engine=None, alert_store=None) -> GapReport:
    techniques = load_techniques()
    covered = []
    uncovered = []
    for t in techniques:
        tid = t.get("id", "")
        name = t.get("name", "")
        tactic = t.get("tactic", t.get("tactics", ["unknown"])[0] if t.get("tactics") else "unknown")
        has_detection = False
        rules = []
        alert_count = 0
        if rules_engine:
            for rule in getattr(rules_engine, "rules", []):
                rule_mitre = getattr(rule, "mitre_id", "") or ""
                if tid == rule_mitre or tid.startswith(rule_mitre + ".") or rule_mitre.startswith(tid + "."):
                    has_detection = True
                    rules.append(getattr(rule, "name", ""))
        entry = TechniqueCoverage(
            technique_id=tid, technique_name=name, tactic=tactic,
            has_detection=has_detection, detection_rules=rules, alert_count=alert_count,
        )
        if has_detection:
            covered.append(entry)
        else:
            uncovered.append(entry)
    total = len(techniques)
    return GapReport(
        total_techniques=total,
        covered=len(covered),
        uncovered=len(uncovered),
        coverage_pct=round(len(covered) / max(total, 1) * 100, 1),
        uncovered_techniques=uncovered,
        covered_techniques=covered,
    )
