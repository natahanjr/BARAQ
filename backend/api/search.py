"""Search API: query-language search over events and alerts.

Query examples:
    GET /api/search?q=source=sysmon event_id=4625&earliest=-24h
    GET /api/search?q=index=alerts rule=brute_force | stats count by host
    GET /api/search?q="powershell" | top 10 user
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.search.engine import SearchError, execute_search
from backend.security import actor_name, require_auth

router = APIRouter(prefix="/api/search", tags=["Search"])


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="search string")
    earliest: str | None = Field(None, description="-24h, -7d or ISO timestamp")
    latest: str | None = Field(None, description="-1h, now or ISO timestamp")
    limit: int = Field(500, ge=1, le=10000)
    include_demo: int | None = Field(
        0,
        ge=0,
        le=1,
        description="1 = include demo/test data in the results (default: production only)",
    )


@router.post("")
async def run_search(
    body: SearchRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth=Depends(require_auth),
):
    """Execute a search and return a tabular result set."""
    org = getattr(request.state, "org", "") or ""
    try:
        result = execute_search(
            db,
            body.query,
            org=org,
            earliest=body.earliest,
            latest=body.latest,
            default_limit=body.limit,
            include_demo=bool(body.include_demo),
        )
    except SearchError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    try:
        log_action(
            db,
            actor_name(request),
            "search.run",
            f"ran search: {body.query[:200]}",
            client_ip(request),
        )
    except Exception:
        pass
    return {
        "index": result.index,
        "query": result.query,
        "columns": result.columns,
        "rows": result.rows,
        "total": result.total,
        "elapsed_ms": result.elapsed_ms,
    }


@router.get("/suggest")
async def search_suggest(q: str = Query("", max_length=200)):
    """Field / pipe autocomplete hints for the search bar."""
    fields = [
        "source",
        "category",
        "user",
        "host",
        "event_id",
        "severity",
        "risk",
        "risk_score",
        "rule",
        "status",
        "name",
        "mitre_id",
        "mitre_tactic",
        "detection_method",
        "is_anomaly",
        "org",
        "demo",
        "correlation_id",
    ]
    pipes = [
        "stats count by",
        "timechart span=1h count by",
        "transaction by host",
        "top 10",
        "rare 10",
        "table",
        "fields",
        "sort -",
        "where",
        "limit",
    ]
    token = q.strip().lower()
    suggestions = []
    for f in fields:
        if f.startswith(token):
            suggestions.append({"type": "field", "text": f"{f}="})
    for p in pipes:
        if p.startswith(token):
            suggestions.append({"type": "pipe", "text": p})
    return {"suggestions": suggestions[:25]}
