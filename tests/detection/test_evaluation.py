"""Phase 2 evaluation metrics runner (SC-001..SC-008).

Replays each labeled scenario through the real pipeline:
raw records -> ingest -> detect (with context) -> persist, then compares
the produced detections against the expected detector set.

Scenario-level metrics (one decision per scenario):
    TP  expected detector fired
    FP  unexpected detector fired on a benign scenario
    FN  expected detector missing on a malicious scenario
    TN  no detection on a benign scenario

The benchmark is small (n = 8) and fully human-labeled; see
docs/phase2/PHASE2_ACCEPTANCE.md for the methodology statement.
"""
from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.engine import run_and_persist
from backend.telemetry.ingestion.pipeline import ingest

from tests.detection.evaluation_data import SCENARIOS, expected_detector_ids
from tests.detection.helpers import stored_events


def _run_scenario(db, scenario: dict) -> set[str]:
    """Replay a scenario end-to-end; return the detector ids that fired.

    Arrival-order simulation: ingest stores enriched events, then each
    stored event is evaluated (with context) exactly as the live pipeline
    would, in deterministic order.
    """
    # Only events ingested by THIS scenario may contribute detections:
    # earlier scenarios' stored events would otherwise be re-evaluated and
    # pollute this scenario's decision (cross-scenario contamination).
    before = {e.fingerprint() for e in stored_events(db)}
    ingest(db, scenario["records"])
    context = DetectionContext(db)
    fired: set[str] = set()
    for event in stored_events(db):
        if event.fingerprint() in before:
            continue
        records = run_and_persist(db, [event], context)
        for record in records:
            fired.add(record.detector_id)
    return fired


def evaluate_scenarios(db) -> dict:
    """Run all scenarios; return per-scenario results + aggregate metrics."""
    results = []
    metrics = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    for scenario in SCENARIOS:
        fired = _run_scenario(db, scenario)
        expected = expected_detector_ids(scenario)
        label = scenario["label"]

        missing = expected - fired
        unexpected = fired - expected
        if label == "TP" and not missing and not unexpected:
            outcome = "TP"
        elif label == "TN" and not fired:
            outcome = "TN"
        elif label == "TN" and fired:
            outcome = "FP"
        elif label == "TP" and missing and not unexpected:
            outcome = "FN"
        else:
            outcome = "FN"
        metrics[outcome] += 1
        results.append(
            {
                "id": scenario["id"],
                "name": scenario["name"],
                "label": label,
                "outcome": outcome,
                "fired": sorted(fired),
                "expected": sorted(expected),
            }
        )

    tp, fp, fn, tn = metrics["TP"], metrics["FP"], metrics["FN"], metrics["TN"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {
        "results": results,
        "metrics": {
            "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
            "n_scenarios": len(SCENARIOS),
        },
    }


def test_all_scenarios_match_labels(db):
    report = evaluate_scenarios(db)
    for result in report["results"]:
        assert result["outcome"] == result["label"], (
            f"{result['id']} {result['name']}: label={result['label']} "
            f"outcome={result['outcome']} fired={result['fired']}"
        )


def test_metrics_perfect_on_benchmark(db):
    """The Phase 2 benchmark must be fully understood: 5 TP, 3 TN."""
    report = evaluate_scenarios(db)
    metrics = report["metrics"]
    assert metrics["TP"] == 5
    assert metrics["TN"] == 3
    assert metrics["FP"] == 0
    assert metrics["FN"] == 0
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["f1"] == 1.0
    assert metrics["fpr"] == 0.0
    assert metrics["n_scenarios"] == 8


def test_evaluation_writes_only_detections(db):
    """The evaluation run must leave v1 state untouched."""
    from sqlalchemy import text

    tables = ("alerts", "incidents", "entity_risk")
    before = {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in tables
    }
    evaluate_scenarios(db)
    after = {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in tables
    }
    assert after == before