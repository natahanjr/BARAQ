from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.search.engine import SearchError, execute_search
from backend.security import require_auth

router = APIRouter(prefix="/api/hunting", tags=["Hunting"])


class HuntRequest(BaseModel):
    query: str
    earliest: str | None = None
    latest: str | None = None
    limit: int = 100


@router.post("/search")
async def hunt_events(
    body: HuntRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(require_auth),
):
    """Hunt across normalized events with the pipe-based query language.

    Example: 'source=sysmon user=admin | stats count by event_id'
    """
    org = getattr(request.state, "org", "") or ""
    try:
        result = execute_search(
            db,
            body.query,
            org=org,
            earliest=body.earliest,
            latest=body.latest,
            default_limit=body.limit,
        )
    except SearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "index": result.index,
        "query": result.query,
        "columns": result.columns,
        "rows": result.rows,
        "total": result.total,
        "elapsed_ms": result.elapsed_ms,
    }


@router.get("/search")
async def hunt_events_get(
    q: str = Query(..., description="query"),
    earliest: str | None = None,
    latest: str | None = None,
    limit: int = Query(100, ge=1, le=10000),
    request: Request = None,
    db: Session = Depends(get_db),
    _auth=Depends(require_auth),
):
    org = getattr(request.state, "org", "") or ""
    try:
        result = execute_search(
            db, q, org=org, earliest=earliest, latest=latest, default_limit=limit
        )
    except SearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "index": result.index,
        "query": result.query,
        "columns": result.columns,
        "rows": result.rows,
        "total": result.total,
        "elapsed_ms": result.elapsed_ms,
    }
