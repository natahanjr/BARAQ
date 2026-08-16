"""Saved searches & dashboards API - analyst workspace.

Analysts save hunt queries (with their time window) and build dashboards of
panels on top of them; the backend renders each panel by running its search
and post-aggregating for the panel visualization (table / count / top).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import Dashboard, SavedSearch
from backend.search.engine import SearchError, execute_search
from backend.security import actor_name, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/saved",
    tags=["saved"],
    dependencies=[Depends(require_auth)],
)


class SavedSearchCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    query: str = Field(..., min_length=1)
    earliest: str = Field("-24h", max_length=32)
    latest: str = Field("", max_length=32)


class SavedSearchUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=2000)
    query: str | None = Field(None, min_length=1)
    earliest: str | None = Field(None, max_length=32)
    latest: str | None = Field(None, max_length=32)


class Panel(BaseModel):
    id: str = Field("", max_length=64)
    title: str = Field("", max_length=128)
    saved_search_id: int | None = None
    query: str | None = Field(None, max_length=2000)
    viz: str = Field("table", pattern="^(table|count|top|area)$")
    field: str = Field("", max_length=64)
    limit: int = Field(10, ge=1, le=100)
    cols: int = Field(2, ge=1, le=4)


class DashboardCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = Field("", max_length=2000)
    panels: list[Panel] = Field(default_factory=list)


class DashboardUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=2000)
    panels: list[Panel] | None = None


def _org_scope(request: Request) -> str:
    return tenant_scope(request) or ""


def _get_saved(db: Session, saved_id: int) -> SavedSearch:
    row = db.get(SavedSearch, saved_id)
    if row is None:
        raise HTTPException(404, "saved search not found")
    return row


def _get_dashboard(db: Session, dashboard_id: int) -> Dashboard:
    row = db.get(Dashboard, dashboard_id)
    if row is None:
        raise HTTPException(404, "dashboard not found")
    return row


def _visible_org_filter(model, org: str):
    # "" = global searches (visible to everyone); otherwise scope to the org.
    return or_(model.org == "", model.org == org)


# ---------------------------------------------------------------------------
# saved searches
# ---------------------------------------------------------------------------
@router.get("/searches")
def list_saved_searches(request: Request, db: Session = Depends(get_db)):
    """All saved searches visible to the caller (global + own org)."""
    org = _org_scope(request)
    rows = db.scalars(
        select(SavedSearch)
        .where(_visible_org_filter(SavedSearch, org))
        .order_by(SavedSearch.name)
    ).all()
    return {"total": len(rows), "searches": [s.to_dict() for s in rows]}


@router.post("/searches")
def create_saved_search(
    body: SavedSearchCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Save a search query for one-click re-runs."""
    org = _org_scope(request)
    duplicate = db.scalars(
        select(SavedSearch).where(
            SavedSearch.name == body.name.strip(),
            SavedSearch.org == org,
        )
    ).first()
    if duplicate:
        raise HTTPException(409, f"saved search '{body.name}' already exists")
    row = SavedSearch(
        name=body.name.strip(),
        description=body.description,
        query=body.query,
        earliest=body.earliest,
        latest=body.latest,
        owner=actor_name(request) or "",
        org=org,
    )
    db.add(row)
    db.commit()
    return row.to_dict()


@router.patch("/searches/{saved_id}")
def update_saved_search(
    saved_id: int,
    body: SavedSearchUpdate,
    db: Session = Depends(get_db),
):
    row = _get_saved(db, saved_id)
    for key, value in body.model_dump(exclude_none=True).items():
        setattr(row, key, value)
    db.commit()
    return row.to_dict()


@router.delete("/searches/{saved_id}")
def delete_saved_search(saved_id: int, db: Session = Depends(get_db)):
    row = _get_saved(db, saved_id)
    db.delete(row)
    db.commit()
    return {"deleted": True, "id": saved_id}


@router.post("/searches/{saved_id}/run")
def run_saved_search(
    saved_id: int,
    request: Request,
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    """Execute a saved search and return the tabular result set."""
    row = _get_saved(db, saved_id)
    org = _org_scope(request)
    try:
        result = execute_search(
            db,
            row.query,
            org=org,
            earliest=row.earliest or "-24h",
            latest=row.latest or None,
            default_limit=1000,
            include_demo=bool(include_demo),
        )
    except SearchError as exc:
        raise HTTPException(400, str(exc))
    return {
        "id": row.id,
        "name": row.name,
        "columns": result.columns,
        "rows": result.rows,
        "total": result.total,
        "elapsed_ms": result.elapsed_ms,
    }


# ---------------------------------------------------------------------------
# dashboards
# ---------------------------------------------------------------------------
@router.get("/dashboards")
def list_dashboards(request: Request, db: Session = Depends(get_db)):
    """All dashboards visible to the caller (global + own org)."""
    org = _org_scope(request)
    rows = db.scalars(
        select(Dashboard)
        .where(_visible_org_filter(Dashboard, org))
        .order_by(Dashboard.name)
    ).all()
    return {"total": len(rows), "dashboards": [d.to_dict() for d in rows]}


@router.post("/dashboards")
def create_dashboard(
    body: DashboardCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    org = _org_scope(request)
    panels = []
    for panel in body.panels:
        panel_data = panel.model_dump()
        if not panel_data.get("id"):
            panel_data["id"] = uuid.uuid4().hex[:8]
        if not panel_data.get("title"):
            panel_data["title"] = panel_data.get("query") or "Panel"
        panels.append(panel_data)
    row = Dashboard(
        name=body.name.strip(),
        description=body.description,
        panels=panels,
        owner=actor_name(request) or "",
        org=org,
    )
    db.add(row)
    db.commit()
    return row.to_dict()


@router.patch("/dashboards/{dashboard_id}")
def update_dashboard(
    dashboard_id: int,
    body: DashboardUpdate,
    db: Session = Depends(get_db),
):
    row = _get_dashboard(db, dashboard_id)
    updates = body.model_dump(exclude_none=True)
    if "panels" in updates:
        panels = []
        for panel in body.panels:
            panel_data = panel.model_dump()
            if not panel_data.get("id"):
                panel_data["id"] = uuid.uuid4().hex[:8]
            panels.append(panel_data)
        updates["panels"] = panels
    for key, value in updates.items():
        setattr(row, key, value)
    db.commit()
    return row.to_dict()


@router.delete("/dashboards/{dashboard_id}")
def delete_dashboard(dashboard_id: int, db: Session = Depends(get_db)):
    row = _get_dashboard(db, dashboard_id)
    db.delete(row)
    db.commit()
    return {"deleted": True, "id": dashboard_id}


def _render_panel(
    db: Session, panel: dict, org: str, include_demo: bool = False
) -> dict:
    """Run a panel's search and post-aggregate for its visualization."""
    query = panel.get("query")
    saved_id = panel.get("saved_search_id")
    if saved_id:
        saved = db.get(SavedSearch, saved_id)
        if saved is None:
            return {"id": panel.get("id"), "title": panel.get("title"), "error": "saved search deleted"}
        query = saved.query
        earliest = saved.earliest or "-24h"
        latest = saved.latest or None
    else:
        earliest = "-24h"
        latest = None
    if not query:
        return {"id": panel.get("id"), "title": panel.get("title"), "error": "panel has no query"}
    try:
        result = execute_search(
            db, query, org=org, earliest=earliest, latest=latest,
            default_limit=1000, include_demo=include_demo,
        )
    except SearchError as exc:
        return {"id": panel.get("id"), "title": panel.get("title"), "error": str(exc)}
    viz = panel.get("viz", "table")
    field = panel.get("field", "")
    limit = max(1, min(100, int(panel.get("limit", 10))))
    out: dict = {
        "id": panel.get("id"),
        "title": panel.get("title") or (query or "Panel"),
        "viz": viz,
        "columns": result.columns,
        "rows": result.rows,
        "total": result.total,
        "elapsed_ms": result.elapsed_ms,
    }
    if viz in ("count", "top", "area") and result.columns:
        count_idx = 0
        if result.columns and result.columns[-1] == "count":
            count_idx = len(result.columns) - 1
        if viz == "count":
            out["count"] = sum(
                r[count_idx] if len(r) > count_idx and isinstance(r[count_idx], (int, float)) else 1
                for r in result.rows
            )
        elif viz == "top":
            target = field or (result.columns[0] if result.columns else "")
            if not target or target not in result.columns:
                return {**out, "error": f"field {target!r} not in results"}
            idx = result.columns.index(target)
            out["data"] = [
                {"name": r[idx], "count": r[count_idx] if len(r) > count_idx and isinstance(r[count_idx], (int, float)) else 1}
                for r in result.rows[:limit]
            ]
        elif viz == "area":
            if result.columns and result.columns[0] == "_time":
                value_idx = 1 if len(result.columns) > 1 else 0
                out["data"] = [
                    {
                        "t": r[0],
                        "value": r[value_idx]
                        if len(r) > value_idx and isinstance(r[value_idx], (int, float))
                        else 0,
                    }
                    for r in result.rows[:limit]
                ]
                return out
            time_idx = next(
                (i for i, c in enumerate(result.columns) if c in ("timestamp", "created_at")), 0
            )
            target = field or (result.columns[-1] if result.columns else "count")
            if target in result.columns:
                value_idx = result.columns.index(target)
            else:
                value_idx = len(result.columns) - 1
            out["data"] = [
                {
                    "t": r[time_idx] if len(r) > time_idx else "",
                    "value": r[value_idx] if len(r) > value_idx else 0,
                }
                for r in result.rows[:limit]
            ]
    return out


@router.get("/dashboards/{dashboard_id}/render")
def render_dashboard(
    dashboard_id: int,
    request: Request,
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    """Render every panel of a dashboard by executing its searches."""
    row = _get_dashboard(db, dashboard_id)
    org = _org_scope(request)
    panels = [
        _render_panel(db, panel, org, include_demo=bool(include_demo))
        for panel in (row.panels or [])
    ]
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "panels": panels,
    }