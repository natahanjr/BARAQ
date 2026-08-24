"""Evaluation Framework (isolated scenario mode).

Runs the 5 attack scenarios plus a benign baseline through the full
detection pipeline (rules engine + alerting) inside a throwaway temp
database. The production DB is never touched by detection - only the
resulting ``EvaluationRun`` metric rows are persisted as history.

Per scenario the raw fixture records are persisted to the temp DB, the
rules engine + alerting run over them, and a confusion matrix is built:

- TP: scenario events linked to an alert, or the scenario's expected
  rule fired (aggregate/connection-level scenarios).
- FN: scenario positives minus TP.
- FP/TN: baseline records linked to alerts / clean baseline records.
"""
from __future__ import annotations

import logging

logger = logging.getLogger("baraq.evaluation")

#: The five attack scenarios and the rule expected to catch each one.
SCENARIO_RULE = {
    "brute_force": "brute_force",
    "powershell": "suspicious_powershell",
    "privilege_escalation": "privilege_escalation",
    "persistence": "persistence",
    "port_scan": "network_recon",
}


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    """Standard confusion-matrix metrics with zero-division guards."""
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "total_samples": total,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_positive_rate": fpr,
    }


def run_evaluation(db, with_ml: bool = True) -> dict:
    """Run the 5 scenarios + baseline in an isolated temp DB.

    Returns the per-scenario + overall metrics and persists only the
    ``EvaluationRun`` history rows into the production DB.
    """
    from tests import fixtures

    from backend.database.models import EvaluationRun
    from backend.evaluation.holdout import (
        _cleanup,
        _empty_session,
        _persist,
        _run_test_detection,
    )

    test_db, engine, path = _empty_session()
    try:
        # ---- Negative class: benign baseline ------------------------------
        baseline_records = fixtures.benign_baseline(60)
        baseline_events, _baseline_conns, n_baseline = _persist(test_db, baseline_records)

        # ---- Positive class: five attack scenarios ------------------------
        per_scenario: dict[str, dict] = {}
        all_events: list[int] = []
        n_positives = 0
        for scenario, rule in SCENARIO_RULE.items():
            records = {
                "brute_force": fixtures.brute_force,
                "powershell": fixtures.suspicious_powershell,
                "privilege_escalation": fixtures.privilege_escalation,
                "persistence": fixtures.persistence,
                "port_scan": fixtures.port_scan,
            }[scenario]()
            event_ids, conn_ids, total = _persist(test_db, records)
            conn_ips = sorted({
                r["remote_ip"] for r in records
                if r.get("source") == "network" and r.get("remote_ip")
            })
            per_scenario[scenario] = {
                "rule": rule,
                "event_ids": event_ids,
                "conn_ids": conn_ids,
                "conn_ips": conn_ips,
                "n_positives": total,
            }
            all_events += event_ids
            n_positives += total

        detection = _run_test_detection(test_db)
        fired = detection["fired_rules"]
        linked = detection["linked_event_ids"]
        elapsed = detection["elapsed_ms"]
        #: Actual per-alert latency (last evidence event -> alert creation).
        #: The wall-clock runtime is kept as pipeline overhead for context.
        latency = detection["per_alert_latency_ms"]
        latency_avg_ms = float(latency.get("avg_ms", 0.0))

# ---- Per-scenario + overall confusion matrices --------------------
        #: Honest "detection time" = wall-clock pipeline time. The per-alert
        #: latency field is kept separately in ``info`` - in the evaluation
        #: fixtures are backdated so ``now - last_evidence`` is meaningless.
        runs: list[EvaluationRun] = []
        fp_total = len([e for e in baseline_events if e in linked])
        tp_total = 0
        for scenario, info in per_scenario.items():
            rule = info["rule"]
            rule_fired = rule in fired
            if scenario == "port_scan":
                tp = info["n_positives"] if rule_fired else 0
            else:
                linked_tp = len([e for e in info["event_ids"] if e in linked])
                tp = linked_tp if linked_tp else (info["n_positives"] if rule_fired else 0)
            fn = max(0, info["n_positives"] - tp)
            tn = max(0, n_baseline - fp_total)
            metrics = _metrics(tp, fp_total, tn, fn)
            tp_total += tp
            runs.append(EvaluationRun(
                scenario=scenario,
                total_samples=metrics["total_samples"],
                attack_samples=info["n_positives"],
                baseline_samples=n_baseline,
                true_positives=metrics["true_positives"],
                false_positives=metrics["false_positives"],
                true_negatives=metrics["true_negatives"],
                false_negatives=metrics["false_negatives"],
                accuracy=metrics["accuracy"],
                precision=metrics["precision"],
                recall=metrics["recall"],
                f1_score=metrics["f1_score"],
false_positive_rate=metrics["false_positive_rate"],
                detection_time_ms=round(elapsed, 2),
            ))

        # Baseline row: TN = clean baseline, FP = baseline events linked.
        baseline_metrics = _metrics(0, fp_total, max(0, n_baseline - fp_total), 0)
        runs.append(EvaluationRun(
            scenario="baseline",
            total_samples=baseline_metrics["total_samples"],
            attack_samples=0,
            baseline_samples=n_baseline,
            true_positives=0,
            false_positives=baseline_metrics["false_positives"],
            true_negatives=baseline_metrics["true_negatives"],
            false_negatives=0,
            accuracy=baseline_metrics["accuracy"],
            precision=baseline_metrics["precision"],
            recall=baseline_metrics["recall"],
            f1_score=baseline_metrics["f1_score"],
false_positive_rate=baseline_metrics["false_positive_rate"],
            detection_time_ms=round(elapsed, 2),
        ))

        overall_metrics = _metrics(tp_total, fp_total, max(0, n_baseline - fp_total), n_positives - tp_total)
        overall = EvaluationRun(
            scenario="overall",
            total_samples=overall_metrics["total_samples"],
            attack_samples=n_positives,
            baseline_samples=n_baseline,
            true_positives=overall_metrics["true_positives"],
            false_positives=overall_metrics["false_positives"],
            true_negatives=overall_metrics["true_negatives"],
            false_negatives=overall_metrics["false_negatives"],
            accuracy=overall_metrics["accuracy"],
            precision=overall_metrics["precision"],
            recall=overall_metrics["recall"],
            f1_score=overall_metrics["f1_score"],
false_positive_rate=overall_metrics["false_positive_rate"],
            detection_time_ms=round(elapsed, 2),
        )

# ---- Persist ONLY the metric history (never the alerts) -----------
        db.add(overall)
        for run in runs:
            db.add(run)
        db.commit()

        info = {
            "events_analyzed": n_positives + n_baseline,
            "findings": len(detection["findings"]),
            "rules_fired": len(fired),
            "open_alerts": 0,
            "detection_time_ms": round(elapsed, 2),
            "pipeline_elapsed_ms": round(elapsed, 2),
            "per_alert_latency_ms": latency,
        }
        logger.info(
            "Scenario evaluation: %d positives, %d baseline, %d rules fired",
            n_positives, n_baseline, len(fired),
        )

        result = {
            "runs": [r.to_dict() for r in runs],
            "overall": overall.to_dict(),
            "info": info,
        }
        if with_ml:
            from backend.ml.anomaly import MLAnomalyDetector

            result["ml"] = MLAnomalyDetector().status()
        return result
    finally:
        _cleanup(test_db, engine, path)

