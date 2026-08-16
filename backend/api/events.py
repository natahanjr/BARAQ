"""Events, processes, network API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import NetworkConnection, NormalizedEvent, ProcessRecord
from backend.security import require_auth, tenant_scope

router = APIRouter(prefix="/api", tags=["events"], dependencies=[Depends(require_auth)])


def _events_scope(request: Request) -> str | None:
    """Tenant predicate for the events table (admin sees all)."""
    return tenant_scope(request)


@router.get("/events")
def list_events(
    request: Request,
    event_id: int | None = None,
    user: str | None = None,
    category: str | None = None,
    anomaly: bool | None = None,
    include_demo: int = Query(0, ge=0, le=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    scope = _events_scope(request)
    stmt = select(NormalizedEvent)
    if scope is not None:
        stmt = stmt.where(NormalizedEvent.org == scope)
    if not include_demo:
        stmt = stmt.where(NormalizedEvent.demo.is_(False))
    if event_id:
        stmt = stmt.where(NormalizedEvent.event_id == event_id)
    if user:
        stmt = stmt.where(NormalizedEvent.user.ilike(f"%{user}%"))
    if category:
        stmt = stmt.where(NormalizedEvent.category.ilike(f"%{category}%"))
    if anomaly is not None:
        stmt = stmt.where(NormalizedEvent.is_anomaly == anomaly)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(NormalizedEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [e.to_dict() for e in rows]}


@router.get("/events/statistics")
def event_statistics(request: Request, db: Session = Depends(get_db)):
    scope = _events_scope(request)
    stmt_event = select(NormalizedEvent.event_id, func.count(NormalizedEvent.id))
    stmt_category = select(NormalizedEvent.category, func.count(NormalizedEvent.id))
    if scope is not None:
        stmt_event = stmt_event.where(NormalizedEvent.org == scope)
        stmt_category = stmt_category.where(NormalizedEvent.org == scope)
    by_event = db.execute(
        stmt_event
        .group_by(NormalizedEvent.event_id)
        .order_by(func.count(NormalizedEvent.id).desc())
        .limit(20)
    ).all()
    by_category = db.execute(
        stmt_category
        .group_by(NormalizedEvent.category)
    ).all()
    return {
        "by_event_id": [{"event_id": int(r[0]), "count": int(r[1])} for r in by_event],
        "by_category": [{"category": r[0], "count": int(r[1])} for r in by_category],
    }


@router.get("/events/{event_id}")
def get_event(event_id: int, request: Request, db: Session = Depends(get_db)):
    scope = _events_scope(request)
    stmt = select(NormalizedEvent).where(NormalizedEvent.id == event_id)
    if scope is not None:
        stmt = stmt.where(NormalizedEvent.org == scope)
    event = db.scalars(stmt).first()
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
