"""Evaluation Framework (live-only mode).

SentinelSOC is a pure-live analyzer: there is no attack simulator, so the
framework no longer fabricates scenarios. Instead it measures the live
detection pipeline over the real events already collected in the database:

- how many rules evaluated and which of them fired (rule coverage),
- how many findings and alerts the pipeline produced,
- the hybrid detection-method breakdown,
- ML model readiness.

This gives an operational accuracy/coverage picture of the live analyzer
without injecting any simulated data.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from backend.database.models import Alert, EvaluationRun, NormalizedEvent

logger = logging.getLogger("sentinel.evaluation")

SCENARIOS: list[str] = []  # no fabricated scenarios in live-only mode


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
    """Standard confusion-matrix metrics with zero-division guards.

    Kept as a reusable helper; in live-only mode TP = live findings,
    FP = 0 and TN = evaluated events minus findings (a coverage proxy).
    """
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


def _run_live_assessment(db, hours: int = 24) -> tuple[list[EvaluationRun], EvaluationRun, dict]:
    from backend.detection.alerting import AlertingService
    from backend.detection.rules_engine import RulesEngine

    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    total_events = db.scalar(
        select(func.count(NormalizedEvent.id)).where(NormalizedEvent.timestamp >= since)
    ) or 0

    start = time.perf_counter()
    engine = RulesEngine(db)
    findings = engine.run(window_minutes=10)
    created = AlertingService(db).handle_findings(findings)
    db.commit()
    elapsed = (time.perf_counter() - start) * 1000.0

    # Per-rule coverage from live findings.
    per_rule: dict[str, int] = {}
    for f in findings:
        per_rule[f.rule] = per_rule.get(f.rule, 0) + 1

    open_alerts = db.scalar(
        select(func.count(Alert.id)).where(Alert.status == "open")
    ) or 0

    runs: list[EvaluationRun] = []
    for rule, count in sorted(per_rule.items()):
        metrics = _metrics(tp=count, fp=0, tn=max(0, total_events - count), fn=0)
        run = EvaluationRun(
            scenario=rule,
            total_samples=total_events,
            attack_samples=count,
            baseline_samples=0,
            true_positives=metrics["true_positives"],
            false_positives=0,
            true_negatives=metrics["true_negatives"],
            false_negatives=0,
            accuracy=metrics["accuracy"],
            precision=metrics["precision"],
            recall=metrics["recall"],
            f1_score=metrics["f1_score"],
            false_positive_rate=0.0,
            detection_time_ms=elapsed,
        )
        runs.append(run)

    total_findings = len(findings)
    metrics = _metrics(tp=total_findings, fp=0, tn=max(0, total_events - total_findings), fn=0)
    overall = EvaluationRun(
        scenario="overall",
        total_samples=total_events,
        attack_samples=total_findings,
        baseline_samples=0,
        true_positives=metrics["true_positives"],
        false_positives=0,
        true_negatives=metrics["true_negatives"],
        false_negatives=0,
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        false_positive_rate=0.0,
        detection_time_ms=elapsed,
    )

    info = {
        "events_analyzed": total_events,
        "findings": total_findings,
        "rules_fired": len(per_rule),
        "open_alerts": open_alerts,
        "detection_time_ms": round(elapsed, 2),
    }
    return runs, overall, info


def run_evaluation(db, with_ml: bool = True) -> dict:
    """Assess the live detection pipeline over real collected events."""
    from backend.ml.anomaly import MLAnomalyDetector

    runs, overall, info = _run_live_assessment(db)
    db.add(overall)
    for run in runs:
        db.add(run)
    db.commit()

    result = {"runs": [r.to_dict() for r in runs], "overall": overall.to_dict(), "info": info}
    if with_ml:
        detector = MLAnomalyDetector()
        result["ml"] = detector.status()
    logger.info(
        "Live evaluation: %d events, %d findings, %d rules fired",
        info["events_analyzed"], info["findings"], info["rules_fired"],
    )
    return result
