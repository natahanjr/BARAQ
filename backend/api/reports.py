"""Reports API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import ReportRecord
from backend.reports.generator import generate_report

router = APIRouter(prefix="/api/reports", tags=["reports"])


class ReportRequest(BaseModel):
    report_type: str = "executive"  # executive | technical
    format: str = "pdf"             # pdf | html | json | csv


@router.post("/generate")
def generate(body: ReportRequest, db: Session = Depends(get_db)):
    try:
        return generate_report(db, body.report_type, body.format)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/list")
def list_reports(db: Session = Depends(get_db)):
    rows = db.scalars(select(ReportRecord).order_by(ReportRecord.created_at.desc()).limit(50)).all()
    return {"items": [r.to_dict() for r in rows]}
