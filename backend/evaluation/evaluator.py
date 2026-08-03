"""Evaluation Framework (Upgrade Module 10).

Runs controlled attack scenarios + baseline against the full detection
pipeline (normalize -> persist -> rules -> alert) inside an isolated
temporary database, then computes standard detection metrics:

    accuracy · precision · recall · F1-score · false-positive rate ·
    detection time

Ground truth is derived from the simulator generators: events produced by
attack scenario generators are positive samples; baseline generator events
are negative samples. An event is "detected" when it becomes linked to an
alert (evidence link) or, for network events, when the source participates
in a raised reconnaissance alert.

The evaluation never touches the production database.
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.database.models import (
    Alert,
    AlertEventLink,
    Base,
    EvaluationRun,
    NetworkConnection,
    NormalizedEvent,
)

logger = logging.getLogger("sentinel.evaluation")

SCENARIOS = ["brute_force", "powershell", "privilege_escalation", "persistence", "port_scan", "baseline"]


def _empty_session() -> Session:
    """Fresh in-memory (file-based temp) database session."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="sentinel_eval_")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


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


def _run_scenario(db: Session, scenario: str, manager) -> EvaluationRun:
    from backend.analyzers.normalizer import Normalizer
    from backend.collectors.simulator import AttackSimulator
    from backend.detection.alerting import AlertingService
    from backend.detection.rules_engine import RulesEngine

    start = time.perf_counter()
    simulator = AttackSimulator()
    if scenario == "baseline":
        records = simulator.scenario("baseline")
    else:
        records = simulator.scenario(scenario)

    normalizer = Normalizer()
    attack_event_ids: list[int] = []
    attack_conn_ids: list[int] = []
    baseline_event_ids: list[int] = []
    baseline_conn_ids: list[int] = []
    first_attack_ts = None

    for record in records:
        if record.get("source") == "network":
            conn = NetworkConnection(
                pid=record.get("pid", 0),
                process=record.get("process", ""),
                local_ip=record.get("local_ip", ""),
                local_port=record.get("local_port", 0),
                remote_ip=record.get("remote_ip", ""),
                remote_port=record.get("remote_port", 0),
                state=record.get("state", ""),
                is_listening=record.get("is_listening", False),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            )
            db.add(conn)
            db.flush()
            if scenario == "baseline":
                baseline_conn_ids.append(conn.id)
            else:
                attack_conn_ids.append(conn.id)
        else:
            event = NormalizedEvent(**normalizer.normalize(record))
            db.add(event)
            db.flush()
            if scenario == "baseline":
                baseline_event_ids.append(event.id)
            else:
                attack_event_ids.append(event.id)
                ts = event.timestamp
                if first_attack_ts is None or ts < first_attack_ts:
                    first_attack_ts = ts

    db.commit()

    engine = RulesEngine(db)
    findings = engine.run(window_minutes=10)
    alerting = AlertingService(db)
    created = alerting.handle_findings(findings)
    db.commit()

    # Which evidence events got linked to alerts?
    detected_event_ids: set[int] = set()
    detected_conn_ids: set[int] = set()
    for alert in created:
        links = db.scalars(
            select(AlertEventLink.event_id).where(AlertEventLink.alert_id == alert.id)
        ).all()
        detected_event_ids.update(links)
        if scenario == "port_scan" and alert.rule == "network_recon":
            detected_conn_ids.update(attack_conn_ids)

    tp = len([e for e in attack_event_ids if e in detected_event_ids])
    fn = len(attack_event_ids) - tp
    fp = len([e for e in baseline_event_ids if e in detected_event_ids])
    tn = len(baseline_event_ids) - fp

    # Network ground truth (port scan events are connection records).
    tp_conn = len([c for c in attack_conn_ids if c in detected_conn_ids])
    fn_conn = len(attack_conn_ids) - tp_conn
    fp_conn = len([c for c in baseline_conn_ids if c in detected_conn_ids])
    tn_conn = len(baseline_conn_ids) - fp_conn

    metrics = _metrics(tp + tp_conn, fp + fp_conn, tn + tn_conn, fn + fn_conn)
    elapsed = (time.perf_counter() - start) * 1000.0

    detection_time_ms = 0.0
    if created and first_attack_ts is not None:
        alert_times = [a.created_at.replace(tzinfo=timezone.utc) for a in created if a.created_at]
        if alert_times:
            first_alert = min(alert_times)
            detection_time_ms = max(0.0, (first_alert - first_attack_ts).total_seconds() * 1000.0)

    run = EvaluationRun(
        scenario=scenario,
        total_samples=metrics["total_samples"],
        attack_samples=len(attack_event_ids) + len(attack_conn_ids),
        baseline_samples=len(baseline_event_ids) + len(baseline_conn_ids),
        true_positives=metrics["true_positives"],
        false_positives=metrics["false_positives"],
        true_negatives=metrics["true_negatives"],
        false_negatives=metrics["false_negatives"],
        accuracy=metrics["accuracy"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1_score=metrics["f1_score"],
        false_positive_rate=metrics["false_positive_rate"],
        detection_time_ms=detection_time_ms if elapsed else 0.0,
    )
    db.add(run)
    db.commit()
    logger.info(
        "Evaluation %s: %d samples, TP=%d FP=%d TN=%d FN=%d (%.1f ms)",
        scenario, metrics["total_samples"], metrics["true_positives"],
        metrics["false_positives"], metrics["true_negatives"],
        metrics["false_negatives"], detection_time_ms,
    )
    return run


def _run_ml_evaluation(db: Session) -> dict:
    """Secondary check: how well does the ML layer flag attack events?"""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector()
    train = detector.train(db, hours=24)
    if not train.get("trained"):
        return {"ml_checked": False, "reason": train.get("status", "untrained")}
    analyze = detector.analyze_events(db, hours=24)
    return {
        "ml_checked": True,
        "trained_streams": train.get("streams", []),
        "supervised": train.get("supervised", "none"),
        "ml_flagged": analyze.get("flagged", 0),
        "ml_scored": analyze.get("scored", 0),
    }


def run_evaluation(db: Session, with_ml: bool = True) -> dict:
    """Run the full evaluation suite in an isolated DB and persist results."""
    from backend.collectors.simulator import AttackSimulator

    eval_db = _empty_session()
    eval_engine = eval_db.get_bind()
    db_path = str(eval_engine.url).replace("sqlite:///", "")
    try:
        simulator = AttackSimulator()
        runs: list[dict] = []
        totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        for scenario in SCENARIOS:
            run = _run_scenario(eval_db, scenario, simulator)
            runs.append(run.to_dict())
            totals["tp"] += run.true_positives
            totals["fp"] += run.false_positives
            totals["tn"] += run.true_negatives
            totals["fn"] += run.false_negatives

        overall_metrics = _metrics(totals["tp"], totals["fp"], totals["tn"], totals["fn"])
        overall = EvaluationRun(
            scenario="overall",
            total_samples=overall_metrics["total_samples"],
            attack_samples=sum(r.attack_samples for r in eval_db.scalars(select(EvaluationRun)) if r.scenario != "overall"),
            baseline_samples=sum(r.baseline_samples for r in eval_db.scalars(select(EvaluationRun)) if r.scenario != "overall"),
            true_positives=overall_metrics["true_positives"],
            false_positives=overall_metrics["false_positives"],
            true_negatives=overall_metrics["true_negatives"],
            false_negatives=overall_metrics["false_negatives"],
            accuracy=overall_metrics["accuracy"],
            precision=overall_metrics["precision"],
            recall=overall_metrics["recall"],
            f1_score=overall_metrics["f1_score"],
            false_positive_rate=overall_metrics["false_positive_rate"],
            detection_time_ms=sum(r["detection_time_ms"] for r in runs) / len(runs) if runs else 0.0,
        )
        eval_db.add(overall)
        eval_db.commit()

        # Persist to the production DB for reporting/history.
        result = {"runs": runs, "overall": overall.to_dict()}
        if with_ml:
            result["ml"] = _run_ml_evaluation(eval_db)
        columns = set(EvaluationRun.__table__.columns.keys())
        for run in runs:
            row = {k: v for k, v in run.items() if k in columns and k not in ("id", "created_at")}
            db.add(EvaluationRun(**row))
        overall_row = {
            k: v for k, v in result["overall"].items()
            if k in columns and k not in ("id", "created_at")
        }
        db.add(EvaluationRun(**overall_row))
        db.commit()
        return result
    finally:
        eval_db.close()
        eval_engine.dispose()
        try:
            if db_path and os.path.exists(db_path):
                os.remove(db_path)
        except OSError:  # pragma: no cover
            logger.warning("Could not remove temp evaluation DB %s", db_path)
        logger.info("Evaluation completed; temp database cleaned up")
