"""P1 item 7 tests: explainable risk scoring.

Every alert must carry a structured, machine-readable explanation of its
risk score: the rule-vs-ML composition, the context modifier and each
dynamic adjustment (signal, delta, reason) - not just a number and a
text dump in the evidence.
"""

from __future__ import annotations

import json

import pytest

from backend.database.models import Alert
from backend.risk.scoring import hybrid_parts, hybrid_risk
from tests.conftest import run_simulation


def _alert_created(db, scenario: str = "powershell") -> Alert:
    run_simulation(db, scenario=scenario)
    return db.query(Alert).order_by(Alert.id.asc()).first()


class TestHybridComposition:
    def test_hybrid_parts_sum_to_final(self):
        events = [{"ml_score": 0.7}, {"ml_score": 0.5}]
        final, rule_part, ml_part, level = hybrid_parts(
            severity="high",
            confidence=0.8,
            event_count=3,
            anomaly_scores=events,
        )
        assert abs(final - (rule_part + ml_part)) < 0.02
        assert rule_part > ml_part  # rule carries 0.6 weight
        assert level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        # backward compat: hybrid_risk still returns (final, level)
        f2, _l2 = hybrid_risk(
            severity="high",
            confidence=0.8,
            event_count=3,
            anomaly_scores=events,
        )
        assert f2 == pytest.approx(final, abs=0.02)

    def test_rule_only_when_no_ml(self):
        _, rule_part, ml_part, _ = hybrid_parts(
            severity="medium", confidence=0.5, event_count=1, anomaly_scores=[]
        )
        assert ml_part == 0.0
        assert rule_part > 0.0


class TestStructuredPayload:
    def test_alert_carries_risk_explanation(self, db):
        alert = _alert_created(db)
        assert alert.risk_json is not None
        payload = json.loads(alert.risk_json)
        assert payload["method"] in {"hybrid", "rule"}
        assert payload["final"] == pytest.approx(alert.risk_score, abs=0.5)
        assert payload["rule_share"] >= 0
        assert payload["ml_share"] >= 0
        base = payload["base"]
        assert abs(base - (payload["rule_share"] + payload["ml_share"])) < 0.5
        # final = base * context_modifier + sum(dynamic deltas), clamped 0-100
        expected = base * payload["context_modifier"] + sum(
            a["delta"] for a in payload["adjustments"]
        )
        assert payload["final"] == pytest.approx(
            min(100.0, max(0.0, expected)), abs=1.0
        )
        assert payload["context_modifier"] >= 0.5
        assert isinstance(payload["adjustments"], list)

    def test_to_dict_exposes_explanation(self, db):
        alert = _alert_created(db)
        data = alert.to_dict()
        assert isinstance(data["risk_adjustments"], list)
        assert data["risk_composition"]["rule_share"] >= 0
        assert data["risk_composition"]["base"] >= 0
        assert data["context_modifier"] >= 0.5

    def test_adjustments_match_evidence_text(self, db):
        alert = _alert_created(db, scenario="persistence")
        payload = json.loads(alert.risk_json)
        deltas = {a["signal"]: a["delta"] for a in payload["adjustments"]}
        assert deltas, "persistence scenario must produce risk adjustments"
        for signal, delta in deltas.items():
            assert f"{signal} {delta:+d}" in alert.evidence
        for adj in payload["adjustments"]:
            assert adj.get("note")

    def test_migration_adds_risk_json_column(self, db):
        from sqlalchemy import inspect

        cols = {c["name"] for c in inspect(db.get_bind()).get_columns("alerts")}
        assert "risk_json" in cols
