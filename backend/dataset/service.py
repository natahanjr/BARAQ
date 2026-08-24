"""Dataset collector service - API-facing orchestration."""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import String, func, select
from sqlalchemy.orm import Session

from backend.config import (
    DATASET_COLLECTOR_VERSION,
    DATASET_DIR,
    DATASET_EXPORT_INTERVAL_HOURS,
    DATASET_FORMAT,
    DATASET_NAME,
    DATASET_TARGET_EVENTS,
)
from backend.database.models import (
    DatasetCollection,
    DatasetEvent,
    DatasetExport,
    DatasetExportFile,
    NormalizedEvent,
)

from .collector import active_collection
from .exporter import export_pending

log = logging.getLogger("dataset.service")

_export_thread: threading.Thread | None = None
_export_lock = threading.Lock()


def status(session: Session) -> dict:
    """Collection status + progress + schedule info."""
    coll = active_collection(session, create_if_missing=True)
    if coll is None:
        return {
            "enabled": False,
            "collection": None,
            "progress_percent": 0.0,
            "remaining": 0,
            "next_export": None,
        }

    last = coll.last_export_at or coll.started_at
    next_export = None
    if coll.status != "complete" and last:
        next_export = last + timedelta(hours=coll.export_interval_hours)
    progress = (coll.total_events / coll.target_events * 100.0) if coll.target_events else 0.0

    return {
        "enabled": True,
        "collection": coll.to_dict(),
        "progress_percent": round(progress, 2),
        "remaining": max(0, coll.target_events - coll.total_events),
        "next_export": next_export.isoformat() if next_export else None,
        "collector_version": DATASET_COLLECTOR_VERSION,
    }


def start(session: Session) -> dict:
    """Start a new collection session (or resume the current paused one)."""
    coll = active_collection(session, create_if_missing=False)
    if coll is not None and coll.status == "paused":
        coll.status = "active"
        session.commit()
        return {"status": "active", "collection_id": coll.id, "resumed": True}
    if coll is not None and coll.status == "active":
        return {"status": "active", "collection_id": coll.id, "resumed": False}

    coll = DatasetCollection(
        name=DATASET_NAME,
        status="active",
        target_events=DATASET_TARGET_EVENTS,
        events_per_file=100_000,
        export_interval_hours=DATASET_EXPORT_INTERVAL_HOURS,
        format=DATASET_FORMAT,
        anonymize=False,
        include_labels=True,
    )
    session.add(coll)
    session.commit()
    log.info("Dataset collection session #%s started", coll.id)
    return {"status": "active", "collection_id": coll.id, "resumed": False}


def pause(session: Session) -> dict:
    coll = active_collection(session, create_if_missing=False)
    if coll is None:
        return {"status": "none"}
    if coll.status == "complete":
        return {"status": "complete"}
    coll.status = "paused"
    session.commit()
    return {"status": "paused", "collection_id": coll.id}


def resume(session: Session) -> dict:
    return start(session)


def export_now(session: Session) -> dict:
    """Run an export in a background thread so ingestion is never blocked."""
    coll = active_collection(session, create_if_missing=False)
    if coll is None:
        return {"status": "failed", "error": "no active collection"}
    if coll.total_events == 0:
        return {"status": "skipped", "error": "no events collected yet"}

    global _export_thread
    with _export_lock:
        if _export_thread is not None and _export_thread.is_alive():
            return {"status": "running", "export_id": None}

        def _run() -> None:
            from backend.database.connection import SessionLocal

            worker = SessionLocal()
            try:
                result = export_pending(worker, coll.id, trigger="manual")
                log.info("Manual dataset export: %s", result["status"])
            finally:
                worker.close()

        _export_thread = threading.Thread(target=_run, daemon=True, name="dataset-export")
        _export_thread.start()
        return {"status": "started", "collection_id": coll.id}


def stats(session: Session, collection_id: int | None = None) -> dict:
    """Dataset composition statistics (only populated buckets)."""
    coll = active_collection(session, create_if_missing=False)
    if coll is None:
        return {}
    coll = session.get(DatasetCollection, coll.id)

    base = select(DatasetEvent).where(DatasetEvent.collection_id == coll.id)

    by_type: dict[str, int] = {}
    rows = session.execute(
        select(DatasetEvent.event_type, func.count())
        .where(DatasetEvent.collection_id == coll.id)
        .group_by(DatasetEvent.event_type)
    ).all()
    for event_type, cnt in rows:
        by_type[event_type or "Other"] = int(cnt)

    return {
        "total": coll.total_events,
        "by_event_type": by_type,
        "hosts": _hosts(session, coll.id),
        "users": _users(session, coll.id),
        "alerts": _alerts(session, coll.id),
        "incidents": _incidents(session, coll.id),
        "mitre_techniques": _mitre(session, coll.id),
        "labels": _labels(session, coll.id),
        "first_timestamp": session.execute(
            select(func.min(DatasetEvent.timestamp)).where(
                DatasetEvent.collection_id == coll.id
            )
        ).scalar(),
        "last_timestamp": session.execute(
            select(func.max(DatasetEvent.timestamp)).where(
                DatasetEvent.collection_id == coll.id
            )
        ).scalar(),
    }


def _hosts(session: Session, collection_id: int) -> int:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["host_name"]).where(
            DatasetEvent.collection_id == collection_id
        )
    ).all()
    return len({r[0] for r in rows if r[0]})


def _users(session: Session, collection_id: int) -> int:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["user"]).where(
            DatasetEvent.collection_id == collection_id
        )
    ).all()
    return len({r[0] for r in rows if r[0]})


def _alerts(session: Session, collection_id: int) -> int:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["alert_id"].cast(String)).where(
            DatasetEvent.collection_id == collection_id,
            DatasetEvent.payload_normalized["alert_id"].cast(String) != "",
        )
    ).all()
    return len({r[0] for r in rows if r[0]})


def _incidents(session: Session, collection_id: int) -> int:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["incident_id"].cast(String)).where(
            DatasetEvent.collection_id == collection_id,
            DatasetEvent.payload_normalized["incident_id"].cast(String) != "",
        )
    ).all()
    return len({r[0] for r in rows if r[0]})


def _mitre(session: Session, collection_id: int) -> int:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["mitre_technique"].cast(String)).where(
            DatasetEvent.collection_id == collection_id,
            DatasetEvent.payload_normalized["mitre_technique"].cast(String) != "",
        )
    ).all()
    return len({r[0] for r in rows if r[0]})


def _labels(session: Session, collection_id: int) -> dict[str, int]:
    rows = session.execute(
        select(DatasetEvent.payload_normalized["analyst_label"].cast(String)).where(
            DatasetEvent.collection_id == collection_id,
            DatasetEvent.payload_normalized["analyst_label"].cast(String).isnot(None),
        )
    ).all()
    counts: dict[str, int] = {}
    for (label,) in rows:
        # postgres JSON -> text keeps the surrounding quotes
        lab = str(label).strip('"')
        if not lab:
            continue
        counts[lab] = counts.get(lab, 0) + 1
    return counts


def exports(session: Session, limit: int = 20) -> dict:
    coll = active_collection(session, create_if_missing=False)
    if coll is None:
        return {"items": []}
    rows = session.execute(
        select(DatasetExport)
        .where(DatasetExport.collection_id == coll.id)
        .order_by(DatasetExport.id.desc())
        .limit(limit)
    ).scalars().all()
    return {"items": [e.to_dict() for e in rows]}


def export_detail(session: Session, export_id: int) -> dict:
    export = session.get(DatasetExport, export_id)
    if export is None:
        return None
    files = session.execute(
        select(DatasetExportFile)
        .where(DatasetExportFile.export_id == export.id)
        .order_by(DatasetExportFile.part_number.asc())
    ).scalars().all()
    return {**export.to_dict(), "files": [f.to_dict() for f in files]}


def manifest(session: Session) -> dict | None:
    coll = active_collection(session, create_if_missing=False)
    if coll is None:
        return None
    path = os.path.join(DATASET_DIR, f"{coll.name}_{'manifest.json'}")
    if not os.path.exists(path):
        files = session.execute(
            select(DatasetExportFile)
            .where(DatasetExportFile.collection_id == coll.id)
            .order_by(DatasetExportFile.part_number.asc())
        ).scalars().all()
        if not files:
            return None
        return _manifest_from_db(coll, files)
    import json

    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _manifest_from_db(coll: DatasetCollection, files: list[DatasetExportFile]) -> dict:
    return {
        "dataset_name": coll.name,
        "target_events": coll.target_events,
        "events_per_file": coll.events_per_file,
        "format": coll.format,
        "total_events": coll.total_events,
        "parts": len(files),
        "collection_started": coll.started_at.isoformat() if coll.started_at else None,
        "last_export": coll.last_export_at.isoformat() if coll.last_export_at else None,
        "status": coll.status,
        "completed_at": coll.completed_at.isoformat() if coll.completed_at else None,
        "schema_version": "v1",
        "collector_version": DATASET_COLLECTOR_VERSION,
        "files": [f.to_dict() for f in files],
    }


def update_config(session: Session, changes: dict) -> dict:
    """Update the active collection's tunables (name, targets, flags)."""
    coll = active_collection(session, create_if_missing=True)
    if coll is None:
        return {"status": "none"}
    allowed = {
        "name": lambda v: str(v)[:128],
        "target_events": lambda v: max(1, int(v)),
        "events_per_file": lambda v: max(1, int(v)),
        "export_interval_hours": lambda v: max(1, int(v)),
        "anonymize": lambda v: bool(v),
        "include_labels": lambda v: bool(v),
    }
    for key, clean in allowed.items():
        if key in changes and changes[key] is not None:
            setattr(coll, key, clean(changes[key]))
    session.commit()
    return {"status": coll.status, "collection": coll.to_dict()}