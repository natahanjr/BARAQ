"""System / collection / ML control endpoints."""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.collectors import CollectorManager
from backend.database.connection import get_db, init_db
from backend.ml.anomaly import get_detector
from backend.security import require_admin, require_auth

logger = logging.getLogger("sentinel.api.system")
router = APIRouter(
    prefix="/api/system",
    tags=["system"],
    dependencies=[Depends(require_auth)],
)


def run_pipeline(db: Session, records: list[dict]) -> dict:
    """Full pipeline: normalize -> persist -> detect -> alert."""
    from backend.analyzers.normalizer import Normalizer
    from backend.analyzers.normalizer import Normalizer
    from backend.database.models import (
        DnsQuery,
        EmailMessage,
        FileScan,
        HttpRequest,
        NetworkConnection,
        NormalizedEvent,
        ProcessRecord,
        UsbDevice,
        VulnFinding,
    )
    from backend.detection.alerting import AlertingService
    from backend.detection.rules_engine import RulesEngine, enrich_result

    normalizer = Normalizer()
    saved_events = 0
    saved_processes = 0
    saved_connections = 0
    saved_dns = 0
    saved_http = 0
    saved_emails = 0
    saved_usb = 0
    saved_files = 0
    saved_vulns = 0

    for record in records:
        source = record.get("source")
        if source == "process":
            db.add(ProcessRecord(
                pid=record["pid"], ppid=record.get("ppid", 0),
                name=record.get("name", ""), path=record.get("path", ""),
                command_line=(record.get("raw") or {}).get("cmdline", ""),
                parent_name="", user=record.get("user", ""),
                is_new=record.get("is_new", False),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_processes += 1
        elif source == "network":
            db.add(NetworkConnection(
                pid=record.get("pid", 0), process=record.get("process", ""),
                local_ip=record.get("local_ip", ""), local_port=record.get("local_port", 0),
                remote_ip=record.get("remote_ip", ""), remote_port=record.get("remote_port", 0),
                state=record.get("state", ""), is_listening=record.get("is_listening", False),
                bytes_sent=record.get("bytes_sent", 0), bytes_recv=record.get("bytes_recv", 0),
                duration_seconds=record.get("duration_seconds", 0.0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_connections += 1
        elif source == "dns":
            db.add(DnsQuery(
                process=record.get("process", ""), pid=record.get("pid", 0),
                query=record.get("query", ""), response=record.get("response", ""),
                response_size=record.get("response_size", 0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_dns += 1
        elif source == "http":
            db.add(HttpRequest(
                process=record.get("process", ""), pid=record.get("pid", 0),
                method=record.get("method", "GET"), url=record.get("url", ""),
                host=record.get("host", ""), status_code=record.get("status_code", 0),
                request_body_size=record.get("request_body_size", 0),
                response_body_size=record.get("response_body_size", 0),
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_http += 1
        elif source == "email":
            db.add(EmailMessage(
                sender=record.get("sender", ""), recipient=record.get("recipient", ""),
                subject=record.get("subject", ""), body=record.get("body", ""),
                attachment_types=record.get("attachment_types", ""),
                ip_address=record.get("ip_address", ""),
                received_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_emails += 1
        elif source == "usb":
            db.add(UsbDevice(
                device_name=record.get("device_name", ""), device_id=record.get("device_id", ""),
                vendor=record.get("vendor", ""), serial=record.get("serial", ""),
                inserted_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_usb += 1
        elif source == "malware":
            db.add(FileScan(
                file_path=record.get("file_path", ""), file_name=record.get("file_name", ""),
                sha256=record.get("sha256", ""), md5=record.get("md5", ""),
                size=record.get("size", 0), signed=record.get("signed", False),
                is_malicious=record.get("is_malicious", False),
                signature_name=record.get("signature_name", ""),
                scanned_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_files += 1
        elif source == "vuln":
            db.add(VulnFinding(
                host=record.get("host", ""),
                product=record.get("product", ""),
                version=record.get("version", ""),
                cve_id=record.get("cve_id", ""),
                cvss=float(record.get("cvss", 0.0) or 0.0),
                severity=record.get("severity", "medium"),
                description=record.get("description", ""),
                remediation=record.get("remediation", ""),
                found_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_vulns += 1
        else:
            normalized = normalizer.normalize(record)
            db.add(NormalizedEvent(**normalized))
            saved_events += 1

    db.commit()

    engine = RulesEngine(db)
    findings = engine.run(window_minutes=10)
    alerting = AlertingService(db)
    created = alerting.handle_findings(findings)

    # Outbound streaming: forward the freshly-persisted records to configured
    # Kafka / Redis / Elasticsearch sinks. Never blocks the pipeline - records
    # are enqueued for the background flush worker.
    streamed = 0
    if records or created:
        try:
            from backend.streaming import record_alert, record_event

            host = records[0].get("host", "") if records else ""
            for i, record in enumerate(records):
                payload = dict(record)
                payload["sentinel.seq"] = i
                if host:
                    payload["host"] = host
                record_event(payload)
                streamed += 1
            for alert in created:
                record_alert(alert.to_dict(include_events=True))
                streamed += 1
        except Exception:  # noqa: BLE001 - streaming must never break collection
            logger.debug("Stream forwarding skipped", exc_info=True)

    # Entity graph: keep the intelligence graph fresh with cheap targeted
    # upserts for this batch (full rebuild is available via /api/entities/sync).
    try:
        from backend.graph import get_graph_store, ingest_batch

        ingest_batch(db, get_graph_store(), records, created)
    except Exception:  # noqa: BLE001 - graph must never break collection
        logger.debug("Graph ingest skipped", exc_info=True)

    return {
        "collected": len(records),
        "saved_events": saved_events,
        "saved_processes": saved_processes,
        "saved_connections": saved_connections,
        "saved_dns": saved_dns,
        "saved_http": saved_http,
        "saved_emails": saved_emails,
        "saved_usb": saved_usb,
        "saved_files": saved_files,
        "saved_vulns": saved_vulns,
        "findings": [enrich_result(f) for f in findings],
        "alerts_created": len(created),
        "streamed": streamed,
    }


@router.post("/collect", dependencies=[Depends(require_admin)])
def collect_once(db: Session = Depends(get_db)):
    manager = CollectorManager()
    records = manager.collect()
    if not records:
        return {"message": "No new live records; install pywin32 for full event log access.", "pipeline": None}
    result = run_pipeline(db, records)
    return {"message": "Collection completed", "pipeline": result}


@router.post("/ml/train", dependencies=[Depends(require_admin)])
def ml_train(
    async_mode: bool = Query(True),
    hours: int = Query(24, ge=1, le=168),
    force: bool = Query(False),
    db: Session = Depends(get_db),
):
    from backend.ml.tasks import train_in_background, training_active

    if async_mode:
        scheduled = train_in_background(hours=hours, force=force)
        return {
            "scheduled": scheduled,
            "force": force,
            "message": (
                "Background training started." if scheduled
                else "A training run is already in progress."
            ),
            "training": training_active(),
        }
    result = get_detector().train(db, hours=hours, validate=not force)
    return result


@router.post("/ml/analyze", dependencies=[Depends(require_admin)])
def ml_analyze(hours: int = Query(1, ge=1, le=168), db: Session = Depends(get_db)):
    result = get_detector().analyze_events(db, hours)
    return result


@router.get("/ml/status")
def ml_status():
    from backend.ml.tasks import training_active

    return {**get_detector().status(), "training": training_active()}


@router.get("/ml/explain/alert/{alert_id}")
def ml_explain_alert(alert_id: int, db: Session = Depends(get_db)):
    """Per-evidence-event ML explanations (SHAP/LIME) for an alert.

    Computed under a hard wall-clock budget; slow explainers degrade to a
    permutation fallback so the endpoint never blocks the analyst for long.
    """
    from sqlalchemy.orm import selectinload

    from backend.database.models import Alert
    from backend.ml.explain import explain_alert

    alert = db.get(Alert, alert_id, options=[selectinload(Alert.events).selectinload("*")])
    if not alert:
        from fastapi import HTTPException

        raise HTTPException(404, "Alert not found")
    return {"alert_id": alert_id, "explanations": explain_alert(db, alert)}


@router.get("/ml/explain/event/{event_id}")
def ml_explain_event(event_id: int, db: Session = Depends(get_db)):
    """Explain a single normalised event's anomaly score."""
    from backend.database.models import NormalizedEvent
    from backend.ml.explain import explain_event

    event = db.get(NormalizedEvent, event_id)
    if not event:
        from fastapi import HTTPException

        raise HTTPException(404, "Event not found")
    return explain_event(event, session=db)


@router.get("/stream/status")
def stream_status():
    """Streaming pipeline config + per-sink health."""
    from backend.streaming import status

    return status()


@router.get("/metrics")
def system_metrics(db: Session = Depends(get_db)):
    """Prometheus text exposition (authenticated)."""
    from backend.metrics import collect_metrics

    return Response(collect_metrics(db), media_type="text/plain; version=0.0.4")


@router.get("/status")
def system_status(db: Session = Depends(get_db)):
    from backend.config import EVENT_RETENTION_DAYS, SECRETS_CONFIGURED
    from backend.database.connection import DATABASE_URL

    detector = get_detector()
    dialect = DATABASE_URL.split(":", 1)[0]
    return {
        "application": "SentinelSOC",
        "version": "1.0.0",
        "collecting": True,
        "database": "sqlite" if dialect == "sqlite" else dialect,
        "summary": dashboard.dashboard_summary(db),
        "uptime_seconds": int(time.time() - _START_TIME),
        "setup": {
            "credentials_configured": SECRETS_CONFIGURED,
            "ml_trained": bool(detector.trained_at),
            "retention_days": EVENT_RETENTION_DAYS,
        },
    }


_START_TIME = time.time()
