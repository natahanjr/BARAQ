"""Phase 7 incident evaluation corpus run (spec 7.40)."""
from __future__ import annotations

from backend.incidents.evaluation import run_evaluation
from backend.incidents.evaluation_data import SCENARIOS


def test_all_scenarios_pass(db):
    counts = run_evaluation(db)
    assert counts["scenarios"] == len(SCENARIOS)
    assert counts["passed"] == len(SCENARIOS)
    assert counts["failed"] == 0


def test_scenario_ids_are_unique():
    ids = [s["id"] for s in SCENARIOS]
    assert len(ids) == len(set(ids))
    assert all(s["id"].startswith("INC-") for s in SCENARIOS)


