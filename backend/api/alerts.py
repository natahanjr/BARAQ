"""Alerts API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import Alert, AnalystNote

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


class StatusUpdate(BaseModel):
    status: str


class NoteCreate(BaseModel):
    note: str


@router.get("")
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    page: int = 1,
    page_size: int = 25,
    db: Session = Depends(get_db),
):
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Alert.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [a.to_dict() for a in rows]}


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert.to_dict(include_events=True)


@router.patch("/{alert_id}/status")
def update_status(alert_id: int, body: StatusUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = body.status
    db.commit()
    return alert.to_dict()


@router.post("/{alert_id}/notes")
def add_note(alert_id: int, body: NoteCreate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    note = AnalystNote(alert_id=alert_id, note=body.note)
    db.add(note)
    db.commit()
    return {"id": note.id, "note": note.note, "created_at": note.created_at.isoformat()}
