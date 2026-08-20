"""Phase 6 metrics + evaluation tests (spec 6.55, 6.56, 6.74)."""
from __future__ import annotations

from backend.risk import engine
from backend.risk.evaluation import run_evaluation
from backend.risk.evaluation_data import SCENARIOS
from backend.risk.metrics import risk_metrics
from backend.risk.models import EntityRiskV2Factor

from tests.risk.helpers import (
    RISK_T0,
    finding_evidence,
    group_evidence,
    stored_factors,
    stored_risks,
)


def _seed(db):
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1021.001"], alert_count=10),
        now=RISK_T0,
    )
    engine.apply_group(
        db, group_evidence("g2", "h2", ["T1110"], alert_count=20),
        now=RISK_T0,
    )
    engine.apply_group(
        db, group_evidence("g3", "h3", ["T1059.001"], severity="medium"),
        now=RISK_T0,
    )
    engine.apply_finding(
        db,
        {
            **finding_evidence("CF-000001", ["h1"]),
            "users": [],
            "source_ips": [],
        },
        now=RISK_T0,
    )


def test_metrics_totals(db):
    _seed(db)
    metrics = risk_metrics(db, now=RISK_T0)
    assert metrics["total_entities"] == len(stored_risks(db))
    assert metrics["entities_with_risk"] == metrics["total_entities"]
    assert metrics["medium"] == 1
    assert metrics["max_score"] == 52.0
    assert metrics["average_score"] > 0
    assert metrics["median_score"] > 0
    assert metrics["score_distribution"]["60_79"] >= 0
    assert metrics["rising"] >= 0
    assert metrics["factor_distribution"]["BEHAVIOR_GROUP"] >= 1
    assert metrics["risk_calculations"] > 0
    assert metrics["snapshot_count"] > 0
    assert metrics["factor_expiration_count"] == 0
    assert metrics["calculation_latency"]["p50_ms"] >= 0
    assert metrics["calculation_latency"]["max_ms"] >= metrics["calculation_latency"]["p50_ms"]


def test_metrics_latency_percentiles_order(db):
    _seed(db)
    latency = risk_metrics(db, now=RISK_T0)["calculation_latency"]
    assert latency["p50_ms"] <= latency["p95_ms"] <= latency["p99_ms"] <= latency["max_ms"]


def test_metrics_never_fabricates_accuracy(db):
    _seed(db)
    metrics = risk_metrics(db, now=RISK_T0)
    assert "accuracy" not in metrics
    assert "precision" not in metrics
    assert "recall" not in metrics
    assert set(metrics["score_distribution"]) == {
        "0_19", "20_39", "40_59", "60_79", "80_100",
    }


def test_metrics_score_distribution_sums(db):
    _seed(db)
    metrics = risk_metrics(db, now=RISK_T0)
    buckets = metrics["score_distribution"]
    assert sum(buckets.values()) == metrics["entities_with_risk"]


def test_metrics_concentration_by_entity_type(db):
    _seed(db)
    metrics = risk_metrics(db, now=RISK_T0)
    hosts = metrics["by_entity_type"]["HOST"]
    assert hosts["total"] == 3
    assert hosts["medium"] == 1
    assert sum(
        band["total"]
        for band in metrics["by_entity_type"].values()
    ) == metrics["total_entities"]


def test_evaluation_reports_raw_scenario_counts(db):
    counts = run_evaluation(db)
    assert counts["scenarios"] == 27
    assert counts["passed"] == 27
    assert counts["failed"] == 0


def test_evaluation_never_fabricates_accuracy(db):
    counts = run_evaluation(db)
    assert "accuracy" not in counts
    assert set(counts) == {"scenarios", "passed", "failed"}


def test_every_scenario_has_full_shape():
    for scenario in SCENARIOS:
        assert scenario["id"].startswith("RISK-")
        assert scenario["description"]
        assert scenario["steps"]
        assert scenario["expected"]
        for step in scenario["steps"]:
            assert "at" in step
            assert any(
                key in step for key in ("evidence", "replay", "expire",
                                        "recalculate_entities", "propagate")
            )