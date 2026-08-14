"""Reports API endpoints."""
from __future__ import annotations

from enum import Enum
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import ReportRecord, ReportSchedule
from backend.reports.generator import generate_report
from backend.security import actor_name, require_admin, require_auth

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
        result = generate_report(db, body.report_type.value, body.format.value)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    log_action(db, actor_name(request), "report.generate", "report", result.get("file_path", ""),
               f"{body.report_type.value} / {body.format.value}", client_ip(request))
    return result


@router.get("/list")
def list_reports(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    rows = db.scalars(select(ReportRecord).order_by(ReportRecord.created_at.desc()).limit(limit)).all()
    return {"items": [r.to_dict() for r in rows]}


# ---------------------------------------------------------------------------
# Scheduled reports (roadmap 6.2)
# ---------------------------------------------------------------------------
@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db)):
    """List scheduled-report definitions with last-run state."""
    rows = db.scalars(select(ReportSchedule).order_by(ReportSchedule.id)).all()
    return {"items": [r.to_dict() for r in rows]}


@router.post("/schedules", dependencies=[Depends(require_admin)])
def create_schedule(body: ScheduleRequest, request: Request, db: Session = Depends(get_db)):
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
    log_action(db, actor_name(request), "report.schedule.create", "report_schedule", str(row.id),
               f"{body.name} ({body.report_type.value}/{body.format.value})", client_ip(request))
    return row.to_dict()


@router.patch("/schedules/{schedule_id}", dependencies=[Depends(require_admin)])
def update_schedule(schedule_id: int, body: ScheduleRequest, db: Session = Depends(get_db)):
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
    log_action(db, actor_name(request), "report.schedule.delete", "report_schedule", str(schedule_id),
               row.name, client_ip(request))
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
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(500, f"Report generation failed: {exc}") from exc
    log_action(db, actor_name(request), "report.schedule.run", "report_schedule", str(schedule_id),
               row.name, client_ip(request))
    return result
