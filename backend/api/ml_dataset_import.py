"""API endpoints for external SOC dataset import (BOTSv1, BOTES, Security-Datasets).

Provides REST endpoints to:
- List available external dataset sources
- Start background import tasks
- Track import progress
- Cancel running imports
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.ml.dataset_import import import_manager
from backend.security import actor_name, require_admin, require_auth

router = APIRouter(
    prefix="/api/ml/datasets/import",
    tags=["ml-dataset-import"],
    dependencies=[Depends(require_auth)],
)


class ImportRequest(BaseModel):
    dataset: str
    max_events: int = 0
    github_token: str = ""


@router.get("/sources")
def list_sources():
    """List available external SOC dataset sources."""
    return import_manager.list_sources()


@router.post("/start", dependencies=[Depends(require_admin)])
def start_import(req: ImportRequest, request: Request, db: Session = Depends(get_db)):
    """Start a background import task for an external dataset.

    Returns a task_id that can be used to poll progress.
    """
    try:
        task = import_manager.start_import(
            req.dataset,
            max_events=req.max_events,
            github_token=req.github_token,
        )
        log_action(
            db,
            actor_name(request),
            "ml.dataset_import.start",
            "import_task",
            task.task_id,
            f"dataset={req.dataset} max_events={req.max_events}",
            client_ip(request),
        )
        return {
            "task_id": task.task_id,
            "dataset": task.dataset,
            "status": task.status,
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/tasks")
def list_tasks():
    """List all import tasks."""
    tasks = import_manager.list_tasks()
    return [
        {
            "task_id": t.task_id,
            "dataset": t.dataset,
            "status": t.status,
            "progress": round(t.progress, 3),
            "total_events": t.total_events,
            "loaded_events": t.loaded_events,
            "skipped_events": t.skipped_events,
            "errors": t.errors[:20],
            "started_at": t.started_at.isoformat() if t.started_at else None,
            "completed_at": t.completed_at.isoformat() if t.completed_at else None,
            "error_message": t.error_message,
        }
        for t in tasks
    ]


@router.get("/tasks/{task_id}")
def get_task(task_id: str):
    """Get status of a specific import task."""
    task = import_manager.get_task(task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    return {
        "task_id": task.task_id,
        "dataset": task.dataset,
        "status": task.status,
        "progress": round(task.progress, 3),
        "total_events": task.total_events,
        "loaded_events": task.loaded_events,
        "skipped_events": task.skipped_events,
        "errors": task.errors[:20],
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "completed_at": task.completed_at.isoformat() if task.completed_at else None,
        "error_message": task.error_message,
    }


@router.post("/tasks/{task_id}/cancel", dependencies=[Depends(require_admin)])
def cancel_task(task_id: str):
    """Cancel a running import task."""
    if import_manager.cancel_task(task_id):
        return {"status": "cancelled"}
    raise HTTPException(400, "Task cannot be cancelled (not found or already running)")
