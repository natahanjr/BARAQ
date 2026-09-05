"""UEBA API — user entity behavior analytics endpoints."""
import logging
from collections import defaultdict

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import NormalizedEvent
from backend.security import require_auth

router = APIRouter(prefix="/api/ueba", tags=["ueba"], dependencies=[Depends(require_auth)])

logger = logging.getLogger("baraq.ueba.api")


def _build_baselines(db: Session, limit: int = 50):
    """Build per-user baselines from event telemetry."""
    from backend.ml.ueba import UEBAEngine

    engine = UEBAEngine()

    user_rows = db.execute(
        select(NormalizedEvent.user, __import__('sqlalchemy').func.count().label("cnt"))
        .where(NormalizedEvent.user != "-")
        .where(NormalizedEvent.user != "")
        .group_by(NormalizedEvent.user)
        .order_by(__import__('sqlalchemy').func.count().desc())
        .limit(limit)
    ).all()

    baselines = []
    for row in user_rows:
        username = row[0]
        if not username:
            continue

        events_q = db.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.user == username)
            .order_by(NormalizedEvent.id.desc())
            .limit(500)
        ).scalars().all()

        events = []
        for ev in events_q:
            events.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
                "host": ev.host or "",
                "process_name": (ev.raw_json or {}).get("process_name", (ev.raw_json or {}).get("NewProcessName", "")),
                "src_ip": (ev.raw_json or {}).get("src_ip", (ev.raw_json or {}).get("IpAddress", "")),
            })

        baseline = engine.build_baseline(username, events)

        baselines.append({
            "user": username,
            "username": username,
            "baseline": {
                "login_hours": baseline.login_hours,
                "typical_hosts": baseline.typical_hosts,
                "typical_processes": baseline.typical_processes[:5],
                "known_ips": baseline.typical_ips,
            },
            "risk_score": baseline.risk_score,
            "event_count_30d": baseline.event_count_30d,
            "avg_daily_events": baseline.avg_daily_events,
            "unique_days_active": baseline.unique_days_active,
            "volume_spikes": 0,
        })

    return baselines, engine


def _detect_anomalies(db: Session, baselines: list, ueba_engine):
    """Detect anomalies by comparing recent events against baselines."""
    from datetime import UTC, datetime, timedelta

    anomalies = []
    cutoff = datetime.now(UTC) - timedelta(hours=24)

    recent = db.execute(
        select(NormalizedEvent)
        .where(NormalizedEvent.timestamp >= cutoff)
        .order_by(NormalizedEvent.id.desc())
        .limit(500)
    ).scalars().all()

    for b in baselines:
        username = b.get("username") or b.get("user")
        if not username:
            continue

        user_events = [ev for ev in recent if ev.user == username]
        if not user_events:
            continue

        events = []
        for ev in user_events:
            events.append({
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else "",
                "host": ev.host or "",
                "process_name": (ev.raw_json or {}).get("process_name", ""),
                "src_ip": (ev.raw_json or {}).get("src_ip", ""),
            })

        detected = ueba_engine.detect_anomalies(username, events)
        for a in detected:
            anomalies.append({
                "user": username,
                "username": username,
                "type": a["type"],
                "severity": a.get("severity", "medium"),
                "description": _anomaly_description(a),
                "timestamp": events[0].get("timestamp", "") if events else "",
                "risk_score": _anomaly_risk(a),
            })

    return anomalies


def _anomaly_description(a: dict) -> str:
    t = a["type"]
    if t == "unusual_hours":
        return f"Activity at unusual hours: {', '.join(str(h) + ':00' for h in a.get('hours', []))}"
    if t == "new_host":
        return f"Activity from new host(s): {', '.join(a.get('hosts', []))}"
    if t == "new_ip":
        return f"Activity from new IP(s): {', '.join(a.get('ips', []))}"
    if t == "event_volume_spike":
        return f"Event volume spike: {a.get('current', 0)} events (baseline avg: {a.get('baseline_avg', 0)})"
    return f"Anomaly: {t}"


def _anomaly_risk(a: dict) -> float:
    sev = a.get("severity", "medium")
    if sev == "critical":
        return 0.9
    if sev == "high":
        return 0.7
    if sev == "medium":
        return 0.5
    return 0.3


@router.get("/baselines")
async def get_baselines(db: Session = Depends(get_db)):
    """Return behavioral baselines for all profiled users."""
    try:
        items, _ = _build_baselines(db)
        return {"items": items}
    except Exception as e:
        logger.exception("Failed to build baselines")
        return {"items": [], "error": str(e)}


@router.get("/anomalies")
async def get_anomalies(db: Session = Depends(get_db)):
    """Return detected behavioral anomalies."""
    try:
        baselines, engine = _build_baselines(db, limit=20)
        items = _detect_anomalies(db, baselines, engine)
        return {"items": items}
    except Exception as e:
        logger.exception("Failed to detect anomalies")
        return {"items": [], "error": str(e)}
