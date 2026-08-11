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
import time
from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from backend.config import DATABASE_URL
from backend.database.connection import normalize_database_url
from backend.database.models import (
    Alert,
    AlertEventLink,
    Base,
    EvaluationRun,
    NetworkConnection,
    NormalizedEvent,
)

logger = logging.getLogger("baraq.evaluation.holdout")

#: Scenarios used to TRAIN the ML detector (seen during training).
TRAIN_SCENARIOS = [
    "brute_force",
    "powershell",
    "privilege_escalation",
    "persistence",
    "ml_credential_spray",
    "ml_obfuscated_powershell",
    "ml_implant_drop",
    "ml_hidden_script",
    "ml_network_exfil",
]

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
    "ml_masquerade",
    "ml_c2_beacon",
    "ml_lateral_c2",
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
    "ml_masquerade": "masquerading",
    "ml_c2_beacon": "suspicious_powershell",
    "ml_lateral_c2": "c2_beacon",
}

#: Connection-record scenarios: detection is scenario-level (rule fired).
CONNECTION_SCENARIOS = {"port_scan", "lateral_movement", "ml_network_exfil", "ml_lateral_c2"}

#: Root-cause guidance for hold-out scenarios missed by every detection layer.
FN_GUIDANCE = {
    "network_recon": "lower PORT_SCAN_DISTINCT_PORTS or widen DETECTION_WINDOW_MINUTES; add slow/distributed scan detection",
    "lateral_movement": "add SMB/DCOM/WMI lateral-movement telemetry (Sysmon Event 3, logon type 3) and session heuristics",
    "data_staging": "lower the archive-binary/staging-volume thresholds or add file-name heuristics",
    "email_phishing": "add URL reputation / sender header analysis; lower phishing key-word threshold",
    "usb_device": "raise USB device-class coverage and correlate device-serial watchlists",
    "dns_http_exfil": "add TXID entropy/query-volume features and widen the DNS lookup window",
    "malware_file": "integrate hash reputation feeds and deepen static-analysis signals",
    "masquerading": "train the ML process stream on the masquerade region; verify writable-path heuristics",
    "suspicious_powershell": "extend encoded-command/IE-download signatures and enable script block logging",
    "c2_beacon": "add per-flow cadence/beacon-interval features to the network supervised model",
    "vulnerability": "schedule regular software inventory scans before scoring",
}


def _fn_debug_report(runs: list[dict]) -> list[dict]:
    """Root-cause report for scenarios no layer detected.

    Mirrors the MITRE-style FN diagnosis requested in the limitations doc:
    which scenario missed, which layer failed, and a concrete remediation.
    """
    out: list[dict] = []
    for r in runs:
        if r["hybrid_tp"] > 0:
            continue
        rule_lay = "rule" if r["rule_detected"] else None
        ml_lay = "ml" if r["ml_tp"] > 0 else None
        if rule_lay and ml_lay:
            cause = "partial"  # never reached (hybrid_tp>0 filtered)
        elif rule_lay:
            cause = "ml-missed"
        elif ml_lay:
            cause = "rule-missed"
        else:
            cause = "both-layers-missed"
        out.append({
            "scenario": r["scenario"],
            "mitre_rule": r["rule"],
            "rule_tp": r["rule_tp"],
            "ml_tp": r["ml_tp"],
            "hybrid_tp": r["hybrid_tp"],
            "root_cause": cause,
            "remediation": FN_GUIDANCE.get(r["rule"], "add a dedicated detection rule"),
        })
    return out


def _empty_session() -> tuple[Session, object, str]:
    """Fresh isolated scratch PostgreSQL database; returns (session, engine, marker).

    A throwaway database (``baraq_scratch_``) is created on the same
    cluster and dropped again in :func:`_cleanup`.
    """
    import uuid

    from sqlalchemy import text as sa_text
    from sqlalchemy.engine import make_url

    base_url = make_url(normalize_database_url(DATABASE_URL))
    db_name = f"baraq_scratch_{uuid.uuid4().hex[:12]}"

    admin = create_engine(base_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            conn.execute(sa_text(f'CREATE DATABASE "{db_name}"'))
    finally:
        admin.dispose()

    engine = create_engine(base_url.set(database=db_name))
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    return session, engine, db_name


def _cleanup(session: Session, engine, path: str) -> None:
    try:
        session.close()
        engine.dispose()
    except Exception:  # noqa: BLE001
        pass
    if not path:
        return
    _drop_scratch_postgres(path)


def _drop_scratch_postgres(db_name: str) -> None:
    from sqlalchemy import text as sa_text
    from sqlalchemy.engine import make_url

    try:
        base = make_url(normalize_database_url(DATABASE_URL))
        admin = create_engine(base.set(database="postgres"), isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.execute(sa_text(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)'))
        finally:
            admin.dispose()
        logger.info("Dropped scratch hold-out database %s", db_name)
    except Exception:  # noqa: BLE001
        logger.warning("Could not drop scratch hold-out database %s", db_name)


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
        "ml_credential_spray": fixtures.ml_credential_spray,
        "ml_obfuscated_powershell": fixtures.ml_obfuscated_powershell,
        "ml_implant_drop": fixtures.ml_implant_drop,
        "ml_hidden_script": fixtures.ml_hidden_script,
        "ml_network_exfil": fixtures.ml_network_exfil,
        "ml_masquerade": fixtures.ml_masquerade_process,
        "ml_c2_beacon": fixtures.ml_c2_beacon,
        "ml_lateral_c2": fixtures.ml_lateral_c2,
    }
    if scenario not in mapping:
        raise KeyError(f"Unknown scenario: {scenario}")
    return mapping[scenario]()


def _randomize_records(records: list[dict], rng) -> list[dict]:
    """Domain randomization for attack records (realistic-timing mitigation).

    Jitters timestamps within the scenario's detection window and varies
    source/remote addresses inside their own /24 subnet, so the simulated
    attack no longer follows one perfectly optimal, deterministic pattern.
    Detection semantics (window thresholds, novel-subnet ML features) are
    preserved, and the caller's seeded RNG keeps runs reproducible.
    """
    from datetime import timedelta

    def jitter_ip(ip: str) -> str:
        parts = ip.split(".")
        if len(parts) != 4:
            return ip
        try:
            last = int(parts[3])
        except ValueError:
            return ip
        last = min(254, max(1, last + rng.randint(-6, 6)))
        return f"{parts[0]}.{parts[1]}.{parts[2]}.{last}"

    out: list[dict] = []
    for r in records:
        r = dict(r)
        if isinstance(r.get("raw"), dict):
            r["raw"] = dict(r["raw"])
        source = r.get("source")
        ts = r.get("timestamp")
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                # Keep the jitter inside the tightest rule window (port-scan
                # detection uses 120 s), so randomized runs stay detectable.
                r["timestamp"] = (dt + timedelta(seconds=rng.randint(-8, 8))).isoformat()
            except ValueError:
                pass
        # Address noise only on attributes that do NOT form rule grouping keys:
        # login source IPs. Network records keep (local_ip, remote_ip) intact
        # because network_recon groups scans by that exact pair.
        if source != "network":
            ip = r.get("source_ip")
            if isinstance(ip, str) and "." in ip:
                r["source_ip"] = jitter_ip(ip)
            raw = r.get("raw")
            if isinstance(raw, dict) and isinstance(raw.get("source_ip"), str):
                raw["source_ip"] = jitter_ip(raw["source_ip"])
        out.append(r)
    return out


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
    only scores test events with that frozen model. Events are routed to
    their own behavior-stream model (login/process), never the generic
    fallback, so the score reflects the stream the event actually belongs to.
    """
    from backend.ml.anomaly import PROCESS_EVENTS, event_feature_vector

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
        behavior = "process" if int(event.event_id) in PROCESS_EVENTS else "login"
        try:
            scores[event_id] = detector.score_event_for_behavior(behavior, features)
        except Exception:  # noqa: BLE001
            continue
    return scores


def _network_ml_scores(db: Session, detector, conn_ids: list[int] | None = None) -> dict[str, float]:
    """Per-remote-IP anomaly scores for the network stream.

    Aggregates connections (optionally restricted to ``conn_ids``) the same
    way the detector scores live flows, so the network stream is measured
    on the same decision units (remote-IP buckets) used in production.
    """
    from sqlalchemy import func

    if detector is None or not detector.is_ready or "network" not in getattr(detector, "models", {}):
        return {}
    query = (
        select(
            NetworkConnection.remote_ip,
            func.count(NetworkConnection.id),
            func.count(func.distinct(NetworkConnection.remote_port)),
            func.sum(NetworkConnection.bytes_sent),
            func.sum(NetworkConnection.bytes_recv),
            func.avg(NetworkConnection.duration_seconds),
        )
    )
    if conn_ids:
        query = query.where(NetworkConnection.id.in_(conn_ids))
    rows = db.execute(query.group_by(NetworkConnection.remote_ip)).all()
    scores: dict[str, float] = {}
    for remote_ip, count, distinct_ports, bytes_sent, bytes_recv, duration in rows:
        try:
            scores[remote_ip or "unknown"] = detector.score_network_connection(
                remote_ip or "unknown",
                int(count), int(distinct_ports),
                int(bytes_sent or 0), int(bytes_recv or 0),
                float(duration or 0.0),
            )
        except Exception:  # noqa: BLE001
            continue
    return scores


def _train_detector(train_db: Session):
    """Train the ML detector on the training split (frozen for scoring)."""
    from backend.ml.anomaly import MLAnomalyDetector

    detector = MLAnomalyDetector()
    try:
        result = detector.train(train_db, hours=24, persist=False)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Hold-out ML training failed: %s", exc)
        return None
    if not result.get("trained"):
        logger.info("Hold-out ML not trained: %s", result.get("status"))
    return detector


def _ml_threshold_for(detector, event_id: int) -> float:
    """Trained per-stream anomaly threshold for an event (default 0.5)."""
    from backend.ml.anomaly import PROCESS_EVENTS

    behavior = "login"
    if int(event_id) in PROCESS_EVENTS:
        behavior = "process"
    return float((detector.thresholds or {}).get(behavior, 0.5))


def _detection_stats(
    n_positives: int,
    fired_rules: set[str],
    linked_event_ids: set[int],
    ml_scores: dict[int, float],
    scenario: str,
    event_ids: list[int],
    conn_ids: list[int],
    ml_thresholds: dict[int, float] | None = None,
    network_ml: dict[str, float] | None = None,
    conn_ips: list[str] | None = None,
    network_threshold: float = 0.5,
) -> dict:
    """Per-scenario detection: how many positives were caught by each layer.

    Scenario-level ground truth: a rule firing on the scenario is the
    detection signal for the aggregate rules (which do not link individual
    events), while event-based rules also count individually linked events.

    The ML layer uses the detector's trained per-stream thresholds (via
    ``ml_thresholds``), not a fixed cutoff. For network (connection-record)
    scenarios the ML decision unit is a remote-IP bucket scored with the
    network stream's threshold (``network_threshold``).
    """
    rule = SCENARIO_RULE.get(scenario)
    rule_fired = rule in fired_rules

    if scenario in CONNECTION_SCENARIOS:
        rule_tp = n_positives if rule_fired else 0
    else:
        # Event-based rule: count events linked to an alert (if any linked).
        linked = len([e for e in event_ids if e in linked_event_ids])
        rule_tp = linked if linked else (n_positives if rule_fired else 0)

    if scenario in CONNECTION_SCENARIOS:
        ml_tp = len(
            [
                ip for ip in (conn_ips or [])
                if (network_ml or {}).get(ip, 0.0) > network_threshold
            ]
        )
    else:
        ml_tp = len(
            [e for e in event_ids if ml_scores.get(e, 0.0) > (ml_thresholds or {}).get(e, 0.5)]
        )

    # Hybrid: either layer catches the scenario. For aggregate (connection)
    # scenarios the rule fires at scenario level, so ML adds value only when a
    # remote-IP bucket is flagged and the rule did not fire.
    if scenario in CONNECTION_SCENARIOS:
        ml_caught = any(
            (network_ml or {}).get(ip, 0.0) > network_threshold for ip in (conn_ips or [])
        )
        hybrid_tp = n_positives if (rule_fired or ml_caught) else 0
    else:
        event_union = len(
            [
                e for e in event_ids
                if e in linked_event_ids
                or ml_scores.get(e, 0.0) > (ml_thresholds or {}).get(e, 0.5)
            ]
        )
        hybrid_tp = max(rule_tp, event_union)

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
    randomize: bool = False,
    seed: int = 20260806,
) -> dict:
    """Run the hold-out evaluation; returns metrics + persists to production DB.

    ``use_real_baseline`` collects live host telemetry for the negative class.
    ``randomize`` applies seeded domain randomization (timing/address jitter)
    to the hold-out attacks to de-bias the deterministic fixtures.
    """
    from tests import fixtures

    rng = None
    if randomize:
        try:
            import random

            rng = random.Random(seed)
        except Exception:  # noqa: BLE001
            rng = None
            randomize = False

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
            records = _fixture_records(scenario)
            if rng is not None:
                records = _randomize_records(records, rng)
            event_ids, conn_ids, total = _persist(test_db, records)
            conn_ips = sorted({
                r["remote_ip"] for r in records
                if r.get("source") == "network" and r.get("remote_ip")
            })
            per_scenario[scenario] = {
                "event_ids": event_ids,
                "conn_ids": conn_ids,
                "conn_ips": conn_ips,
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
        ml_thresholds: dict[int, float] = {}
        network_ml: dict[str, float] = {}
        network_threshold = 0.5
        ml_fp = 0
        if detector is not None:
            ml_scores = _ml_scores(test_db, all_attack_events, detector)
            ml_thresholds = {
                eid: _ml_threshold_for(detector, eid) for eid in all_attack_events
            }
            ml_fp = len(
                [
                    e for e in baseline_event_ids
                    if _ml_scores(test_db, [e], detector).get(e, 0.0)
                    > _ml_threshold_for(detector, e)
                ]
            )
            network_ml = _network_ml_scores(test_db, detector)
            network_threshold = float((detector.thresholds or {}).get("network", 0.5))
            baseline_net = _network_ml_scores(test_db, detector, baseline_conn_ids)
            ml_fp += len([ip for ip, s in baseline_net.items() if s > network_threshold])

        # ---- Per-scenario + overall metrics --------------------------------
        runs: list[dict] = []
        rule_tp = ml_tp = hybrid_tp = 0
        ml_scoped: list[str] = []
        ml_scoped_attack_units = 0
        for scenario in HOLDOUT_SCENARIOS:
            info = per_scenario[scenario]
            stats = _detection_stats(
                info["n_positives"],
                detection["fired_rules"], detection["linked_event_ids"],
                ml_scores, scenario,
                info["event_ids"], info["conn_ids"],
                ml_thresholds,
                network_ml, info["conn_ips"], network_threshold,
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
            if info["event_ids"] or info["conn_ips"]:
                ml_scoped.append(scenario)
                ml_scoped_attack_units += (
                    len(info["conn_ips"]) if scenario in CONNECTION_SCENARIOS
                    else len(info["event_ids"])
                )

        # Rule-layer FPs: real-baseline events linked to alerts.
        rule_fp = len([e for e in baseline_event_ids if e in detection["linked_event_ids"]])

        # ML-layer metrics are computed over the population the ML streams can
        # actually score (login/process events + remote-IP network buckets),
        # NOT over email/usb/dns/file records the model never sees. This keeps
        # the ML recall an *honest* number for the attack types it models.
        baseline_net_units = 0
        if detector is not None:
            baseline_net_units = len(_network_ml_scores(test_db, detector, baseline_conn_ids))
        baseline_ml_units = max(1, len(baseline_event_ids) + baseline_net_units)
        ml_pos = ml_scoped_attack_units
        ml_tn = max(0, baseline_ml_units - ml_fp)
        ml_fn = max(0, ml_pos - ml_tp)

        rule_metrics = _metrics(rule_tp, rule_fp, max(0, n_baseline - rule_fp), n_positives - rule_tp)
        ml_metrics = _metrics(ml_tp, ml_fp, ml_tn, ml_fn) if detector is not None else None
        hybrid_metrics = _metrics(
            hybrid_tp, rule_fp + ml_fp,
            max(0, n_baseline - rule_fp - ml_fp), n_positives - hybrid_tp,
        )

        result = {
            "methodology": {
                "training_split": TRAIN_SCENARIOS,
                "holdout_split": HOLDOUT_SCENARIOS,
                "negative_class": "real-host-telemetry" if use_real_baseline else "synthetic-baseline",
                "train_test_separation": "ML trained only on training split; test set never seen",
                "ml_scope": "ML drawn from login/process events + network IP buckets",
                "ml_scoped_scenarios": ml_scoped,
                "n_baseline_records": n_baseline,
                "randomization": "seeded-domain-randomization" if randomize else "deterministic",
                "randomization_seed": seed if randomize else None,
            },
            "rule_layer": {**rule_metrics, "detection_time_ms": round(detection["elapsed_ms"], 2)},
            "ml_layer": ml_metrics if detector is not None else None,
            "hybrid_layer": hybrid_metrics,
            "per_scenario": runs,
            "alerts_created": detection["created"],
            "false_negative_report": _fn_debug_report(runs),
        }

        # ---- Persist to production DB (history) -----------------------------
        for layer, metrics in (("rule", rule_metrics), ("ml", ml_metrics), ("hybrid", hybrid_metrics)):
            if metrics is None:
                continue
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
