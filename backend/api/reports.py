"""Reports API endpoints."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.config import REPORT_DIR
from backend.database.connection import get_db
from backend.database.models import ReportRecord, ReportSchedule
from backend.reports.generator import generate_report
from backend.security import actor_name, require_admin, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/reports",
    tags=["reports"],
    dependencies=[Depends(require_auth)],
)


class ReportType(str, Enum):
    executive = "executive"
    technical = "technical"


class ReportFormat(str, Enum):
    pdf = "pdf"
    html = "html"
    json = "json"
    csv = "csv"


class ReportRequest(BaseModel):
    report_type: ReportType = ReportType.executive
    format: ReportFormat = ReportFormat.pdf


class ScheduleRequest(BaseModel):
    name: str = "scheduled"
    report_type: ReportType = ReportType.executive
    format: ReportFormat = ReportFormat.pdf
    every_hours: int = 24
    hour_of_day: int = -1
    email_to: str = ""
    enabled: bool = True


@router.post("/generate")
def generate(body: ReportRequest, request: Request, db: Session = Depends(get_db)):
    try:
        result = generate_report(
            db,
            body.report_type.value,
            body.format.value,
            org=tenant_scope(request),
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    log_action(
        db,
        actor_name(request),
        "report.generate",
        "report",
        result.get("id", ""),
        f"{body.report_type.value} / {body.format.value}",
        client_ip(request),
    )
    return {key: value for key, value in result.items() if key != "file_path"}


@router.get("/list")
def list_reports(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    stmt = select(ReportRecord)
    scope = tenant_scope(request)
    if scope is not None:
        stmt = stmt.where(ReportRecord.org == scope)
    rows = db.scalars(
        stmt.order_by(ReportRecord.created_at.desc()).limit(limit)
    ).all()
    return {"items": [r.to_dict() for r in rows]}


@router.get("/{report_id}/download")
def download_report(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    stmt = select(ReportRecord).where(ReportRecord.id == report_id)
    scope = tenant_scope(request)
    if scope is not None:
        stmt = stmt.where(ReportRecord.org == scope)
    record = db.scalar(stmt)
    if record is None:
        raise HTTPException(404, "Report not found")
    report_root = Path(REPORT_DIR).resolve()
    path = Path(record.file_path).resolve()
    if not path.is_file() or report_root not in path.parents:
        raise HTTPException(404, "Report file not found")
    media_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
    }
    return FileResponse(
        path,
        media_type=media_types.get(record.format, "application/octet-stream"),
        filename=path.name,
        headers={"Cache-Control": "no-store"},
    )


# ---------------------------------------------------------------------------
# Scheduled reports (roadmap 6.2)
# ---------------------------------------------------------------------------
@router.get("/schedules")
def list_schedules(request: Request, db: Session = Depends(get_db)):
    """List scheduled-report definitions with last-run state.

    Schedules carry no tenant column (a single scheduler owns them), so
    mutating them is admin-only. Analysts still get the operational view, but
    recipient addresses are redacted - they are configuration, not alert data.
    """
    rows = db.scalars(select(ReportSchedule).order_by(ReportSchedule.id)).all()
    is_admin = getattr(request.state, "api_role", "") == "admin" or (
        (getattr(request.state, "token_user", None) or {}).get("role") == "admin"
    )
    items = []
    for r in rows:
        item = r.to_dict()
        if not is_admin:
            item["email_to"] = ""
            item["email_to_set"] = bool(r.email_to)
        items.append(item)
    return {"items": items}


@router.post("/schedules", dependencies=[Depends(require_admin)])
def create_schedule(
    body: ScheduleRequest, request: Request, db: Session = Depends(get_db)
):
    if body.every_hours < 1 and body.hour_of_day < 0:
        raise HTTPException(422, "every_hours >= 1 or hour_of_day >= 0 is required")
    row = ReportSchedule(
        name=body.name,
        report_type=body.report_type.value,
        fmt=body.format.value,
        every_hours=body.every_hours,
        hour_of_day=body.hour_of_day,
        email_to=body.email_to,
        enabled=body.enabled,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_action(
        db,
        actor_name(request),
        "report.schedule.create",
        "report_schedule",
        str(row.id),
        f"{body.name} ({body.report_type.value}/{body.format.value})",
        client_ip(request),
    )
    return row.to_dict()


@router.patch("/schedules/{schedule_id}", dependencies=[Depends(require_admin)])
def update_schedule(
    schedule_id: int, body: ScheduleRequest, db: Session = Depends(get_db)
):
    row = db.get(ReportSchedule, schedule_id)
    if not row:
        raise HTTPException(404, "Schedule not found")
    if body.every_hours < 1 and body.hour_of_day < 0:
        raise HTTPException(422, "every_hours >= 1 or hour_of_day >= 0 is required")
    row.name = body.name
    row.report_type = body.report_type.value
    row.fmt = body.format.value
    row.every_hours = body.every_hours
    row.hour_of_day = body.hour_of_day
    row.email_to = body.email_to
    row.enabled = body.enabled
    db.commit()
    db.refresh(row)
    return row.to_dict()


@router.delete("/schedules/{schedule_id}", dependencies=[Depends(require_admin)])
def delete_schedule(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    row = db.get(ReportSchedule, schedule_id)
    if not row:
        raise HTTPException(404, "Schedule not found")
    db.delete(row)
    db.commit()
    log_action(
        db,
        actor_name(request),
        "report.schedule.delete",
        "report_schedule",
        str(schedule_id),
        row.name,
        client_ip(request),
    )
    return {"deleted": schedule_id}


@router.post("/schedules/{schedule_id}/run", dependencies=[Depends(require_admin)])
def run_schedule_now(schedule_id: int, request: Request, db: Session = Depends(get_db)):
    """Generate the report immediately (optionally emailing recipients)."""
    from backend.reports.schedule import run_schedule

    row = db.get(ReportSchedule, schedule_id)
    if not row:
        raise HTTPException(404, "Schedule not found")
    try:
        result = run_schedule(db, row)
    except Exception as exc:
        raise HTTPException(500, f"Report generation failed: {exc}") from exc
    log_action(
        db,
        actor_name(request),
        "report.schedule.run",
        "report_schedule",
        str(schedule_id),
        row.name,
        client_ip(request),
    )
    return {key: value for key, value in result.items() if key != "file_path"}
