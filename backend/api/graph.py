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

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import (
    Alert,
    AlertEventLink,
    NormalizedEvent,
)
from backend.graph import get_graph_store, sync_graph
from backend.security import require_admin, require_auth

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


@router.get("")
def list_entities(
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
    return {"items": rows, "total": len(rows), "kind": kind, "provider": store.name}


@router.get("/status")
def entity_status(db: Session = Depends(get_db)):
    store = get_graph_store()
    return {"ok": True, **store.status(db)}


@router.get("/graph")
def entity_graph(
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
    return store.graph(db, center_kind=kind, center_name=center_name, depth=depth)


@router.get("/{kind}/{name}")
def entity_detail(
    kind: str,
    name: str,
    db: Session = Depends(get_db),
    depth: int = Query(1, ge=0, le=3),
):
    store = get_graph_store()
    kind = _normalize_kind(kind)
    if kind not in VALID_KINDS:
        raise HTTPException(400, f"unknown entity kind: {kind}")
    entity = store.get_entity(db, kind, name)
    if not entity:
        raise HTTPException(404, f"entity not found: {kind}:{name}")

    subgraph = store.graph(db, center_kind=kind, center_name=name, depth=depth)

    # recent linked alerts (via evidence events carrying this entity)
    alerts: list[dict] = []
    try:

        if kind in ("user", "host"):
            col = NormalizedEvent.user if kind == "user" else NormalizedEvent.host
            arows = db.scalars(
                select(Alert)
                .join(AlertEventLink, AlertEventLink.alert_id == Alert.id)
                .join(NormalizedEvent, NormalizedEvent.id == AlertEventLink.event_id)
                .where(col == name)
                .order_by(Alert.created_at.desc())
                .limit(10)
            ).all()
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
