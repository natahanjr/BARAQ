"""Phase 6 evaluation corpus run (spec 6.57-6.58).

Runs the 27 hand-labeled RISK-001..RISK-027 scenarios through the real
engine and verifies every expected score/severity/state/trend/factor set.
No accuracy percentage is ever fabricated (6.56).
"""

from __future__ import annotations

from backend.risk.evaluation import run_evaluation
from backend.risk.evaluation_data import SCENARIOS


def test_all_27_scenarios_pass(db):
    counts = run_evaluation(db)
    assert counts["scenarios"] == 27
    assert counts["passed"] == 27
    assert counts["failed"] == 0


def test_scenario_ids_are_unique():
    ids = [scenario["id"] for scenario in SCENARIOS]
    assert len(ids) == len(set(ids))
    assert all(scenario["id"].startswith("RISK-") for scenario in SCENARIOS)
