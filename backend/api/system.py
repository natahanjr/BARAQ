"""System / collection / ML control endpoints."""
from __future__ import annotations

import logging
import time

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.collectors import CollectorManager
from backend.database.connection import get_db, init_db
from backend.ml.anomaly import get_detector

logger = logging.getLogger("sentinel.api.system")
router = APIRouter(prefix="/api/system", tags=["system"])


def run_pipeline(db: Session, records: list[dict]) -> dict:
    """Full pipeline: normalize -> persist -> detect -> alert."""
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
        else:
            normalized = normalizer.normalize(record)
            db.add(NormalizedEvent(**normalized))
            saved_events += 1

    db.commit()

    engine = RulesEngine(db)
    findings = engine.run(window_minutes=10)
    alerting = AlertingService(db)
    created = alerting.handle_findings(findings)

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
        "findings": [enrich_result(f) for f in findings],
        "alerts_created": len(created),
    }


@router.post("/collect")
def collect_once(db: Session = Depends(get_db)):
    manager = CollectorManager()
    records = manager.collect()
    if not records:
        return {"message": "No new live records; install pywin32 for full event log access.", "pipeline": None}
    result = run_pipeline(db, records)
    return {"message": "Collection completed", "pipeline": result}


@router.post("/ml/train")
def ml_train(db: Session = Depends(get_db)):
    result = get_detector().train(db)
    return result


@router.post("/ml/analyze")
def ml_analyze(hours: int = 1, db: Session = Depends(get_db)):
    result = get_detector().analyze_events(db, hours)
    return result


@router.get("/ml/status")
def ml_status():
    return get_detector().status()


@router.get("/status")
def system_status(db: Session = Depends(get_db)):
    return {
        "application": "SentinelSOC",
        "version": "1.0.0",
        "collecting": True,
        "database": "sqlite",
        "summary": dashboard.dashboard_summary(db),
        "uptime_seconds": int(time.time() - _START_TIME),
    }


_START_TIME = time.time()
