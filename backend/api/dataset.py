"""Research dataset collector API (Telemetry -> Dataset Collector)."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.config import DATASET_DIR
from backend.database.connection import get_db
from backend.database.models import DatasetExportFile
from backend.security import actor_name, require_admin, require_auth

from backend.dataset import (
    export_detail,
    export_now,
    exports,
    manifest,
    pause,
    resume,
    start,
    stats,
    status,
    update_config,
)

router = APIRouter(
    prefix="/api/telemetry/dataset",
    tags=["dataset"],
    dependencies=[Depends(require_auth)],
)


@router.get("")
def dataset_status(db: Session = Depends(get_db)):
    """Collection status, progress, next export."""
    return status(db)


@router.get("/stats")
def dataset_stats(db: Session = Depends(get_db)):
    """Dataset composition statistics."""
    return stats(db)


@router.get("/exports")
def dataset_exports(limit: int = 20, db: Session = Depends(get_db)):
    return exports(db, limit=min(max(limit, 1), 100))


@router.get("/exports/{export_id}")
def dataset_export_detail(export_id: int, db: Session = Depends(get_db)):
    row = export_detail(db, export_id)
    if row is None:
        raise HTTPException(404, "Export not found")
    return row


@router.get("/manifest")
def dataset_manifest(db: Session = Depends(get_db)):
    row = manifest(db)
    if row is None:
        raise HTTPException(404, "No manifest yet")
    return row


@router.post("/start", dependencies=[Depends(require_admin)])
def dataset_start(request: Request, db: Session = Depends(get_db)):
    result = start(db)
    log_action(
        db, actor_name(request), "dataset.start", "dataset_collection",
        str(result.get("collection_id", "")), str(result), client_ip(request),
    )
    return result


@router.post("/pause", dependencies=[Depends(require_admin)])
def dataset_pause(request: Request, db: Session = Depends(get_db)):
    result = pause(db)
    log_action(
        db, actor_name(request), "dataset.pause", "dataset_collection",
        str(result.get("collection_id", "")), str(result), client_ip(request),
    )
    return result


@router.post("/resume", dependencies=[Depends(require_admin)])
def dataset_resume(request: Request, db: Session = Depends(get_db)):
    result = resume(db)
    log_action(
        db, actor_name(request), "dataset.resume", "dataset_collection",
        str(result.get("collection_id", "")), str(result), client_ip(request),
    )
    return result


@router.post("/export", dependencies=[Depends(require_admin)])
def dataset_export(request: Request, db: Session = Depends(get_db)):
    """Manual export (runs in a background thread, ingestion unaffected)."""
    result = export_now(db)
    log_action(
        db, actor_name(request), "dataset.export", "dataset_collection",
        str(result.get("collection_id", "")), str(result), client_ip(request),
    )
    return result


@router.post("/config", dependencies=[Depends(require_admin)])
def dataset_config(body: dict, request: Request, db: Session = Depends(get_db)):
    result = update_config(db, body)
    log_action(
        db, actor_name(request), "dataset.config", "dataset_collection",
        str(result.get("collection", {}).get("id", "")), str(result), client_ip(request),
    )
    return result


@router.get("/download/{file_id}", dependencies=[Depends(require_admin)])
def dataset_download(file_id: int, db: Session = Depends(get_db)):
    """Download one CSV part (admin only - research data may be sensitive)."""
    row = db.get(DatasetExportFile, file_id)
    if row is None:
        raise HTTPException(404, "File not found")
    path = os.path.join(DATASET_DIR, row.filename)
    if not os.path.exists(path):
        raise HTTPException(404, "File missing on disk")
    return FileResponse(
        path,
        media_type="text/csv",
        filename=row.filename,
        headers={"X-SHA256": row.sha256},
    )


@router.get("/download", dependencies=[Depends(require_admin)])
def dataset_download_latest(db: Session = Depends(get_db)):
    """Download the most recent CSV part."""
    row = db.query(DatasetExportFile).order_by(DatasetExportFile.part_number.desc()).first()
    if row is None:
        raise HTTPException(404, "No CSV files yet")
    path = os.path.join(DATASET_DIR, row.filename)
    if not os.path.exists(path):
        raise HTTPException(404, "File missing on disk")
    return FileResponse(
        path,
        media_type="text/csv",
        filename=row.filename,
        headers={"X-SHA256": row.sha256},
    )