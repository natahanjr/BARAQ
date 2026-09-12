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
    offset: int = 0
    sort_by: str | None = None
    sort_order: str = "desc"

    def model_post_init(self, __context) -> None:
        """Validate sort parameters."""
        if self.sort_by:
            # Only allow alphanumeric characters and underscores to prevent injection
            import re
            if not re.match(r'^[a-zA-Z0-9_]+$', self.sort_by):
                raise ValueError("sort_by must contain only alphanumeric characters and underscores")
        if self.sort_order not in ("asc", "desc"):
            raise ValueError("sort_order must be 'asc' or 'desc'")


@router.post("/search")
async def hunt_events(
    body: HuntRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(require_auth),
):
    """Hunt across normalized events with the pipe-based query language.

    Example: 'source=sysmon user=admin | stats count by event_id'

    Supports pagination via offset/limit and sorting via sort_by/sort_order.
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
        # Apply pagination
        total_rows = len(result.rows)
        paginated_rows = result.rows[body.offset:body.offset + body.limit]
        return {
            "index": result.index,
            "query": result.query,
            "columns": result.columns,
            "rows": paginated_rows,
            "total": total_rows,
            "offset": body.offset,
            "limit": body.limit,
            "has_more": body.offset + body.limit < total_rows,
            "elapsed_ms": result.elapsed_ms,
        }
    except SearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/search")
async def hunt_events_get(
    request: Request,
    q: str = Query(..., description="query"),
    earliest: str | None = None,
    latest: str | None = None,
    limit: int = Query(100, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    sort_by: str | None = Query(None, description="Column to sort by"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: Session = Depends(get_db),
    _auth=Depends(require_auth),
):
    org = getattr(request.state, "org", "") or ""
    try:
        result = execute_search(
            db, q, org=org, earliest=earliest, latest=latest, default_limit=limit
        )
        # Apply pagination
        total_rows = len(result.rows)
        paginated_rows = result.rows[offset:offset + limit]
        return {
            "index": result.index,
            "query": result.query,
            "columns": result.columns,
            "rows": paginated_rows,
            "total": total_rows,
            "offset": offset,
            "limit": limit,
            "has_more": offset + limit < total_rows,
            "elapsed_ms": result.elapsed_ms,
        }
    except SearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
