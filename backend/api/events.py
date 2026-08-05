"""Events, processes, network API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import NetworkConnection, NormalizedEvent, ProcessRecord
from backend.security import require_auth

router = APIRouter(prefix="/api", tags=["events"], dependencies=[Depends(require_auth)])


@router.get("/events")
def list_events(
    event_id: int | None = None,
    user: str | None = None,
    category: str | None = None,
    anomaly: bool | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    stmt = select(NormalizedEvent)
    if event_id:
        stmt = stmt.where(NormalizedEvent.event_id == event_id)
    if user:
        stmt = stmt.where(NormalizedEvent.user.ilike(f"%{user}%"))
    if category:
        stmt = stmt.where(NormalizedEvent.category == category)
    if anomaly is not None:
        stmt = stmt.where(NormalizedEvent.is_anomaly == anomaly)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(NormalizedEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [e.to_dict() for e in rows]}


@router.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    event = db.get(NormalizedEvent, event_id)
    if not event:
        raise HTTPException(404, "Event not found")
    return event.to_dict()


@router.get("/processes")
def list_processes(limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(ProcessRecord).order_by(ProcessRecord.observed_at.desc()).limit(limit)
    ).all()
    return {"total": len(rows), "items": [p.to_dict() for p in rows]}


@router.get("/network")
def list_network(
    limit: int = Query(200, ge=1, le=1000),
    remote_ip: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(NetworkConnection)
    if remote_ip:
        stmt = stmt.where(NetworkConnection.remote_ip == remote_ip)
    rows = db.scalars(stmt.order_by(NetworkConnection.observed_at.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [c.to_dict() for c in rows]}


@router.get("/events/statistics")
def event_statistics(db: Session = Depends(get_db)):
    by_event = db.execute(
        select(NormalizedEvent.event_id, func.count(NormalizedEvent.id))
        .group_by(NormalizedEvent.event_id)
        .order_by(func.count(NormalizedEvent.id).desc())
        .limit(20)
    ).all()
    by_category = db.execute(
        select(NormalizedEvent.category, func.count(NormalizedEvent.id))
        .group_by(NormalizedEvent.category)
    ).all()
    return {
        "by_event_id": [{"event_id": int(r[0]), "count": int(r[1])} for r in by_event],
        "by_category": [{"category": r[0], "count": int(r[1])} for r in by_category],
    }
