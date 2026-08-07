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
from backend.database.models import ReportRecord
from backend.reports.generator import generate_report
from backend.security import actor_name, require_auth

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
