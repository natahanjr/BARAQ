"""Entity intelligence graph API (entity investigation graph).

Endpoints (all provider-agnostic through :class:`GraphStore`):

* ``GET /api/entities`` - page entities (kind / risk / text filter).
* ``GET /api/entities/status`` - provider health + counts.
* ``GET /api/entities/graph?center_kind=&center_name=&depth=`` - node/edge
  payload for the interactive entity graph.
* ``GET /api/entities/{kind}/{name}`` - entity profile (risk, properties,
  relationships, recent events, linked alerts).
* ``POST /api/entities/sync`` - rebuild the graph from telemetry (admin).

Entity kinds: ``user | device | process | ip | domain | file | technique |
threat_actor``.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    AlertEventLink,
    NormalizedEvent,
)
from backend.graph import get_graph_store, sync_graph
from backend.security import require_admin, require_auth, tenant_scope

router = APIRouter(
    prefix="/api/entities",
    tags=["entities"],
    dependencies=[Depends(require_auth)],
)

#: valid kinds for path/query validation + UI colouring
VALID_KINDS = {
    "user",
    "device",
    "host",
    "process",
    "ip",
    "domain",
    "file",
    "technique",
    "threat_actor",
}


def _normalize_kind(kind: str | None) -> str | None:
    if not kind:
        return kind
    # 'host' is a query/UI alias for the stored kind 'device'
    return "device" if kind == "host" else kind


def _visible_entity_names(db: Session, org: str | None) -> set[str] | None:
    """Entity names this tenant has actually observed.

    ``entity_nodes`` is a single global namespace (one row per kind+name, no
    org column), so for a tenant-scoped caller the graph is filtered down to
    hosts and accounts that appear in that tenant's own telemetry. Returns
    ``None`` for unrestricted callers (admins without an org filter and
    auth-disabled deployments) and for the central scope, which owns the
    untagged rows.

    TODO: make the graph natively multi-tenant (``entity_nodes.org`` + unique
    on (org, kind, name)); until then this is the isolation boundary.
    """
    if org is None or org == "":
        return None
    rows = db.execute(
        select(NormalizedEvent.host, NormalizedEvent.user)
        .where(NormalizedEvent.org == org)
        .distinct()
    ).all()
    return {str(v).strip().lower() for row in rows for v in row if v}


def _filter_nodes(payload: dict, names: set[str] | None) -> dict:
    """Drop graph nodes/edges the tenant has not observed.

    Node dicts carry ``name``; edge endpoints are ``{"kind","name"}`` dicts.
    """
    if names is None:
        return payload
    nodes = [
        n for n in payload.get("nodes", []) if str(n.get("name", "")).lower() in names
    ]
    edges = []
    for e in payload.get("edges", []):
        src = e.get("source") or {}
        dst = e.get("target") or {}
        src_name = str(src.get("name", "") if isinstance(src, dict) else src).lower()
        dst_name = str(dst.get("name", "") if isinstance(dst, dict) else dst).lower()
        if src_name in names and dst_name in names:
            edges.append(e)
    return {**payload, "nodes": nodes, "edges": edges, "tenant_filtered": True}


@router.get("")
def list_entities(
    request: Request,
    db: Session = Depends(get_db),
    kind: str | None = Query(None),
    min_risk: float = Query(0.0, ge=0.0, le=100.0),
    search: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    store = get_graph_store()
    rows = store.list_entities(
        db,
        kind=_normalize_kind(kind),
        limit=limit,
        offset=offset,
        min_risk=min_risk,
        search=search,
    )
    names = _visible_entity_names(db, tenant_scope(request))
    if names is not None:
        # Over-fetch then filter: the global store cannot filter by tenant, and
        # paging is applied after the tenant filter so a page never leaks names.
        rows = [r for r in rows if str(r.get("name", "")).lower() in names]
    return {"items": rows, "total": len(rows), "kind": kind, "provider": store.name}


@router.get("/status")
def entity_status(db: Session = Depends(get_db)):
    store = get_graph_store()
    return {"ok": True, **store.status(db)}


@router.get("/graph")
def entity_graph(
    request: Request,
    db: Session = Depends(get_db),
    center_kind: str | None = Query(None),
    center_name: str | None = Query(None),
    depth: int = Query(1, ge=0, le=4),
):
    store = get_graph_store()
    kind = _normalize_kind(center_kind) if center_kind else None
    if (center_kind is None) != (center_name is None):
        raise HTTPException(
            400, "center_kind and center_name must be provided together"
        )
    names = _visible_entity_names(db, tenant_scope(request))
    if names is not None and center_name and str(center_name).lower() not in names:
        raise HTTPException(404, f"entity not found: {kind}:{center_name}")
    payload = store.graph(db, center_kind=kind, center_name=center_name, depth=depth)
    return _filter_nodes(payload, names)


@router.get("/{kind}/{name}")
def entity_detail(
    request: Request,
    kind: str,
    name: str,
    db: Session = Depends(get_db),
    depth: int = Query(1, ge=0, le=3),
):
    store = get_graph_store()
    org = tenant_scope(request)
    kind = _normalize_kind(kind)  # type: ignore[assignment]
    if kind not in VALID_KINDS:
        raise HTTPException(400, f"unknown entity kind: {kind}")
    names = _visible_entity_names(db, org)
    if names is not None and str(name).lower() not in names:
        raise HTTPException(404, f"entity not found: {kind}:{name}")
    entity = store.get_entity(db, kind, name)
    if not entity:
        raise HTTPException(404, f"entity not found: {kind}:{name}")

    subgraph = _filter_nodes(
        store.graph(db, center_kind=kind, center_name=name, depth=depth), names
    )

    # recent linked alerts (via evidence events carrying this entity)
    alerts: list[dict] = []
    try:

        if kind in ("user", "host"):
            col = NormalizedEvent.user if kind == "user" else NormalizedEvent.host
            stmt = (
                select(Alert)
                .join(AlertEventLink, AlertEventLink.alert_id == Alert.id)
                .join(NormalizedEvent, NormalizedEvent.id == AlertEventLink.event_id)
                .where(col == name)
                .where(or_(Alert.org == "", NormalizedEvent.org == ""))
                .order_by(Alert.created_at.desc())
                .limit(10)
            )
            if org is not None:
                stmt = stmt.where(Alert.org == org)
            arows = db.scalars(stmt).all()
            alerts = [a.to_dict() for a in arows]
    except Exception:
        import logging

        logging.getLogger("baraq.graph").exception("Alert lookup failed")

    return {
        "entity": entity,
        "subgraph": subgraph,
        "related_alerts": alerts,
        "provider": store.name,
    }


@router.post("/sync", dependencies=[Depends(require_admin)])
def entity_sync(db: Session = Depends(get_db)):
    store = get_graph_store()
    try:
        return sync_graph(db, store)
    except Exception as exc:
        import logging

        logging.getLogger("baraq.graph").exception("Graph sync failed")
        raise HTTPException(500, f"graph sync failed: {exc}") from exc
