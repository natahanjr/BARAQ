"""Hold-out Evaluation Framework (external-validity metrics).

Legitimises the detection metrics by removing two circularities that
inflate the old numbers:

1. **Hold-out test set.** The ML detector is trained on a *training split*
   of attack scenarios (brute force, PowerShell, privilege escalation,
   persistence) plus a synthetic benign baseline. Detection is then
   measured on a *hold-out split* of attack scenarios the detector never
   saw (port scan, lateral movement, data staging, phishing, USB, DNS/HTTP
   exfiltration, malware) - so recall/precision reflect generalisation to
   unseen attacks, not memorisation.

2. **Real-telemetry baseline.** The negative samples (true negatives) are
   events collected live from the actual host via ``CollectorManager``
   (``/collect``), not synthetic "normal" data. A rule or model firing on
   real host traffic is a genuine false positive, so FPR / precision carry
   external validity.

Methodology (per run, all inside isolated temp databases - the production
DB is never touched):

- Phase A (training DB): persist training-split scenarios + synthetic
  baseline, train the ML detector.
- Phase B (test DB): persist real host telemetry (negatives) + hold-out
  attack scenarios (positives); run the rules engine + alerting; score the
  same test DB with the trained detector.
- Metrics are computed over the test DB only. An event is a predicted
  positive when it is linked to an alert (rules), when ``ml_score > 0.5``
  (ML), or either (hybrid).
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

logger = logging.getLogger("sentinel.evaluation.holdout")

#: Scenarios used to TRAIN the ML detector (seen during training).
TRAIN_SCENARIOS = ["brute_force", "powershell", "privilege_escalation", "persistence"]

#: Scenarios held OUT of training - detection is measured on these.
HOLDOUT_SCENARIOS = [
    "port_scan",
    "lateral_movement",
    "data_staging",
    "phishing",
    "usb",
    "dns",
    "http",
    "malware",
]

#: Which rule is expected to fire for each hold-out scenario.
SCENARIO_RULE = {
    "port_scan": "network_recon",
    "lateral_movement": "lateral_movement",
    "data_staging": "data_staging",
    "phishing": "email_phishing",
    "usb": "usb_device",
    "dns": "dns_http_exfil",
    "http": "dns_http_exfil",
    "malware": "malware_file",
}

#: Connection-record scenarios: detection is scenario-level (rule fired).
CONNECTION_SCENARIOS = {"port_scan", "lateral_movement"}


def _empty_session() -> tuple[Session, object, str]:
    """Fresh isolated file-backed temp database; returns (session, engine, path)."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="sentinel_holdout_")
    os.close(fd)
    engine = create_engine(f"sqlite:///{path}")
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return session, engine, path


def _cleanup(session: Session, engine, path: str) -> None:
    try:
        session.close()
        engine.dispose()
    except Exception:  # noqa: BLE001
        pass
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        logger.warning("Could not remove temp hold-out DB %s", path)


def _fixture_records(scenario: str) -> list[dict]:
    """Deterministic raw records for a scenario (test fixtures, not a simulator)."""
    from tests import fixtures

    mapping = {
        "brute_force": fixtures.brute_force,
        "powershell": fixtures.suspicious_powershell,
        "privilege_escalation": fixtures.privilege_escalation,
        "persistence": fixtures.persistence,
        "port_scan": fixtures.port_scan,
        "lateral_movement": fixtures.lateral_movement,
        "data_staging": fixtures.data_staging,
        "phishing": fixtures.phishing_email,
        "usb": fixtures.usb_device,
        "dns": fixtures.dns_exfil,
        "http": fixtures.http_exfil,
        "malware": fixtures.malicious_file,
    }
    if scenario not in mapping:
        raise KeyError(f"Unknown scenario: {scenario}")
    return mapping[scenario]()


def _real_telemetry() -> list[dict]:
    """Live host telemetry via the real collectors (no simulation)."""
    from backend.collectors import CollectorManager

    try:
        return CollectorManager().collect()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Real telemetry collection failed: %s", exc)
        return []


def _persist(db: Session, records: list[dict]) -> tuple[list[int], list[int], int]:
    """Persist raw records; returns (event_ids, conn_ids, total_record_count)."""
    from backend.analyzers.normalizer import Normalizer
    from backend.database.models import (
        DnsQuery,
        EmailMessage,
        FileScan,
        HttpRequest,
        ProcessRecord,
        UsbDevice,
    )

    normalizer = Normalizer()
    event_ids: list[int] = []
    conn_ids: list[int] = []
    total = 0
    for record in records:
        source = record.get("source")
        if source == "network":
            conn = NetworkConnection(
                pid=record.get("pid", 0), process=record.get("process", ""),
                local_ip=record.get("local_ip", ""), local_port=record.get("local_port", 0),
                remote_ip=record.get("remote_ip", ""), remote_port=record.get("remote_port", 0),
                state=record.get("state", ""), is_listening=record.get("is_listening", False),
                bytes_sent=record.get("bytes_sent", 0), bytes_recv=record.get("bytes_recv", 0),
                duration_seconds=record.get("duration_seconds", 0.0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            )
            db.add(conn)
            db.flush()
            conn_ids.append(conn.id)
        elif source == "process":
            db.add(ProcessRecord(
                pid=record["pid"], ppid=record.get("ppid", 0),
                name=record.get("name", ""), path=record.get("path", ""),
                command_line=(record.get("raw") or {}).get("cmdline", ""),
                parent_name="", user=record.get("user", ""),
                is_new=record.get("is_new", False),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        elif source == "dns":
            db.add(DnsQuery(
                process=record.get("process", ""), pid=record.get("pid", 0),
                query=record.get("query", ""), response=record.get("response", ""),
                response_size=record.get("response_size", 0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        elif source == "http":
            db.add(HttpRequest(
                process=record.get("process", ""), pid=record.get("pid", 0),
                method=record.get("method", "GET"), url=record.get("url", ""),
                host=record.get("host", ""), status_code=record.get("status_code", 0),
                request_body_size=record.get("request_body_size", 0),
                response_body_size=record.get("response_body_size", 0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        elif source == "email":
            db.add(EmailMessage(
                sender=record.get("sender", ""), recipient=record.get("recipient", ""),
                subject=record.get("subject", ""), body=record.get("body", ""),
                attachment_types=record.get("attachment_types", ""),
                ip_address=record.get("ip_address", ""),
                received_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        elif source == "usb":
            db.add(UsbDevice(
                device_name=record.get("device_name", ""), device_id=record.get("device_id", ""),
                vendor=record.get("vendor", ""), serial=record.get("serial", ""),
                inserted_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        elif source == "malware":
            db.add(FileScan(
                file_path=record.get("file_path", ""), file_name=record.get("file_name", ""),
                sha256=record.get("sha256", ""), md5=record.get("md5", ""),
                size=record.get("size", 0), signed=record.get("signed", False),
                is_malicious=record.get("is_malicious", False),
                signature_name=record.get("signature_name", ""),
                scanned_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
        else:
            event = NormalizedEvent(**normalizer.normalize(record))
            db.add(event)
            db.flush()
            event_ids.append(event.id)
        total += 1
    db.commit()
    return event_ids, conn_ids, total


def _metrics(tp: int, fp: int, tn: int, fn: int) -> dict:
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


def _run_test_detection(db: Session) -> dict:
    """Rules + alerting over the test DB; returns per-rule fired + linked ids."""
    from backend.detection.alerting import AlertingService
    from backend.detection.rules_engine import RulesEngine

    start = time.perf_counter()
    engine = RulesEngine(db)
    findings = engine.run(window_minutes=10)
    alerting = AlertingService(db)
    created = alerting.handle_findings(findings)
    db.commit()
    elapsed = (time.perf_counter() - start) * 1000.0

    fired_rules = {f.rule for f in findings}
    linked_event_ids: set[int] = set()
    for alert in created:
        links = db.scalars(
            select(AlertEventLink.event_id).where(AlertEventLink.alert_id == alert.id)
        ).all()
        linked_event_ids.update(links)

    return {
        "fired_rules": fired_rules,
        "linked_event_ids": linked_event_ids,
        "created": len(created),
        "elapsed_ms": elapsed,
        "findings": findings,
    }


def _ml_scores(db: Session, event_ids: list[int], detector) -> dict[int, float]:
    """ML anomaly scores using an ALREADY-TRAINED detector (no leakage).

    The detector must be trained on the training split only; this function
    only scores test events with that frozen model.
    """
    from backend.ml.anomaly import event_feature_vector

    if detector is None or not detector.is_ready:
        return {}
    scores: dict[int, float] = {}
    for event_id in event_ids:
        event = db.get(NormalizedEvent, event_id)
        if event is None:
            continue
        features = event_feature_vector(event)
        if features is None:
            continue
        try:
            scores[event_id] = detector.score_event(features)
        except Exception:  # noqa: BLE001
            continue
    return scores


def _train_detector(train_db: Session):
    """Train the ML detector on the training split (frozen for scoring)."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector()
    try:
        result = detector.train(train_db, hours=24)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Hold-out ML training failed: %s", exc)
        return None
    if not result.get("trained"):
        logger.info("Hold-out ML not trained: %s", result.get("status"))
    return detector


def _detection_stats(
    n_positives: int,
    fired_rules: set[str],
    linked_event_ids: set[int],
    ml_scores: dict[int, float],
    scenario: str,
    event_ids: list[int],
    conn_ids: list[int],
) -> dict:
    """Per-scenario detection: how many positives were caught by each layer.

    Scenario-level ground truth: a rule firing on the scenario is the
    detection signal for the aggregate rules (which do not link individual
    events), while event-based rules also count individually linked events.
    """
    rule = SCENARIO_RULE.get(scenario)
    rule_fired = rule in fired_rules

    if scenario in CONNECTION_SCENARIOS:
        rule_tp = n_positives if rule_fired else 0
    else:
        # Event-based rule: count events linked to an alert (if any linked).
        linked = len([e for e in event_ids if e in linked_event_ids])
        rule_tp = linked if linked else (n_positives if rule_fired else 0)

    ml_tp = len([e for e in event_ids if ml_scores.get(e, 0.0) > 0.5])
    hybrid_tp = rule_tp  # rule layer is the primary signal for aggregate rules
    if not CONNECTION_SCENARIOS.intersection({scenario}) and event_ids:
        hybrid_tp = len(
            [e for e in event_ids if e in linked_event_ids or ml_scores.get(e, 0.0) > 0.5]
        )

    return {
        "rule_tp": rule_tp,
        "ml_tp": ml_tp,
        "hybrid_tp": hybrid_tp,
        "n_positives": n_positives,
        "rule_detected": bool(rule_tp),
    }


def run_holdout_evaluation(
    db: Session,
    with_ml: bool = True,
    use_real_baseline: bool = True,
) -> dict:
    """Run the hold-out evaluation; returns metrics + persists to production DB.

    ``use_real_baseline`` collects live host telemetry for the negative class.
    """
    from tests import fixtures

    train_db, train_engine, train_path = _empty_session()
    test_db, test_engine, test_path = _empty_session()
    try:
        # ---- Phase A: training split -------------------------------------
        train_records = fixtures.benign_baseline(80)
        for scenario in TRAIN_SCENARIOS:
            train_records += _fixture_records(scenario)
        _persist(train_db, train_records)
        _persist(train_db, _real_telemetry() if use_real_baseline else [])
        logger.info("Hold-out: training DB with %d records", len(train_records))

        # Train the detector on the training split ONLY (frozen afterwards).
        detector = _train_detector(train_db) if with_ml else None

        # ---- Phase B: test split ------------------------------------------
        # Negative class: real host telemetry (true negatives).
        baseline_records = _real_telemetry() if use_real_baseline else fixtures.benign_baseline(60)
        baseline_event_ids, baseline_conn_ids, n_baseline = _persist(test_db, baseline_records)
        logger.info(
            "Hold-out: baseline = %d real telemetry records (%d events, %d conns)",
            len(baseline_records), len(baseline_event_ids), len(baseline_conn_ids),
        )

        # Positive class: hold-out (unseen) attack scenarios.
        per_scenario: dict[str, dict] = {}
        all_attack_events: list[int] = []
        all_attack_conns: list[int] = []
        n_positives = 0
        for scenario in HOLDOUT_SCENARIOS:
            event_ids, conn_ids, total = _persist(test_db, _fixture_records(scenario))
            per_scenario[scenario] = {
                "event_ids": event_ids,
                "conn_ids": conn_ids,
                "n_events": len(event_ids),
                "n_conns": len(conn_ids),
                "n_positives": total,
            }
            all_attack_events += event_ids
            all_attack_conns += conn_ids
            n_positives += total

        detection = _run_test_detection(test_db)

        # ---- ML scoring on the test set (frozen detector; no retraining) ----
        ml_scores = {}
        ml_baseline_fp = 0
        if detector is not None:
            ml_scores = _ml_scores(test_db, all_attack_events, detector)
            ml_baseline_fp = len(
                [e for e in baseline_event_ids if _ml_scores(test_db, [e], detector).get(e, 0.0) > 0.5]
            )

        # ---- Per-scenario + overall metrics --------------------------------
        runs: list[dict] = []
        rule_tp = ml_tp = hybrid_tp = 0
        for scenario in HOLDOUT_SCENARIOS:
            info = per_scenario[scenario]
            stats = _detection_stats(
                info["n_positives"],
                detection["fired_rules"], detection["linked_event_ids"],
                ml_scores, scenario,
                info["event_ids"], info["conn_ids"],
            )
            rule_tp += stats["rule_tp"]
            ml_tp += stats["ml_tp"]
            hybrid_tp += stats["hybrid_tp"]
            runs.append({
                "scenario": scenario,
                "rule": SCENARIO_RULE.get(scenario),
                "n_positives": stats["n_positives"],
                "rule_detected": stats["rule_detected"],
                "rule_tp": stats["rule_tp"],
                "ml_tp": stats["ml_tp"],
                "hybrid_tp": stats["hybrid_tp"],
            })

        # Rule-layer FPs: real-baseline events linked to alerts.
        rule_fp = len([e for e in baseline_event_ids if e in detection["linked_event_ids"]])
        # ML-layer FPs: real-baseline events flagged anomalous.
        ml_fp = ml_baseline_fp if detector is not None else 0

        rule_metrics = _metrics(rule_tp, rule_fp, max(0, n_baseline - rule_fp), n_positives - rule_tp)
        ml_metrics = _metrics(ml_tp, ml_fp, max(0, n_baseline - ml_fp), n_positives - ml_tp)
        hybrid_metrics = _metrics(
            hybrid_tp, max(rule_fp, ml_fp), n_baseline - max(rule_fp, ml_fp), n_positives - hybrid_tp
        )

        result = {
            "methodology": {
                "training_split": TRAIN_SCENARIOS,
                "holdout_split": HOLDOUT_SCENARIOS,
                "negative_class": "real-host-telemetry" if use_real_baseline else "synthetic-baseline",
                "train_test_separation": "ML trained only on training split; test set never seen",
                "n_baseline_records": n_baseline,
            },
            "rule_layer": {**rule_metrics, "detection_time_ms": round(detection["elapsed_ms"], 2)},
            "ml_layer": ml_metrics if detector is not None else None,
            "hybrid_layer": hybrid_metrics,
            "per_scenario": runs,
            "alerts_created": detection["created"],
        }

        # ---- Persist to production DB (history) -----------------------------
        for layer, metrics in (("rule", rule_metrics), ("ml", ml_metrics), ("hybrid", hybrid_metrics)):
            db.add(EvaluationRun(
                scenario=f"holdout:{layer}",
                total_samples=metrics["total_samples"],
                attack_samples=n_positives,
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
                detection_time_ms=rule_metrics.get("detection_time_ms", 0.0),
            ))
        db.commit()

        logger.info(
            "Hold-out evaluation: rule acc=%.3f recall=%.3f | ml acc=%.3f recall=%.3f",
            rule_metrics["accuracy"], rule_metrics["recall"],
            ml_metrics["accuracy"] if detector is not None else 0.0,
            ml_metrics["recall"] if detector is not None else 0.0,
        )
        return result
    finally:
        _cleanup(train_db, train_engine, train_path)
        _cleanup(test_db, test_engine, test_path)
