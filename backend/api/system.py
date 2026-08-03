"""System / collection / ML control endpoints."""
from __future__ import annotations

import logging
import threading
import time

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.collectors import CollectorManager
from backend.database.connection import get_db, init_db
from backend.ml.anomaly import get_detector

logger = logging.getLogger("sentinel.api.system")
router = APIRouter(prefix="/api/system", tags=["system"])

_pipeline_lock = threading.Lock()


def run_pipeline(db: Session, records: list[dict]) -> dict:
    """Full pipeline: normalize -> persist -> detect -> alert."""
    from backend.analyzers.normalizer import Normalizer
    from backend.database.models import NetworkConnection, NormalizedEvent, ProcessRecord
    from backend.detection.alerting import AlertingService
    from backend.detection.rules_engine import RulesEngine, enrich_result

    normalizer = Normalizer()
    saved_events = 0
    saved_processes = 0
    saved_connections = 0

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
                observed_at=Normalizer._safe_ts(record.get("timestamp")),
            ))
            saved_connections += 1
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


class SimulateRequest(BaseModel):
    scenario: str | None = None


@router.post("/simulate")
def simulate(request: SimulateRequest, db: Session = Depends(get_db)):
    from backend.collectors.simulator import AttackSimulator

    simulator = AttackSimulator()
    records = simulator.scenario(request.scenario) if request.scenario else simulator.collect()
    with _pipeline_lock:
        result = run_pipeline(db, records)
    return {"message": "Simulation completed", "pipeline": result}


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
