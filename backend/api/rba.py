"""Risk-Based Alerting (RBA) API endpoints.

Exposes the entity risk store: the leaderboard of entities with
accumulated risk, per-entity risk timelines (every delta that moved the
score), and the declarative correlation rules loaded from YAML.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.detection.correlation_engine import load_correlation_rules
from backend.detection.tuning import get_tuning, set_tuning
from backend.risk.entity_risk import EntityRiskManager
from backend.security import actor_name, require_admin, require_auth, tenant_scope

logger = logging.getLogger("baraq.api.rba")

router = APIRouter(
    prefix="/api/rba",
    tags=["rba"],
    dependencies=[Depends(require_auth)],
)


def _scoped_org(request: Request) -> str:
    """Org filter for the calling user ('' = their whole scope)."""
    scope = tenant_scope(request)
    return scope or ""


@router.get("/entities")
def rba_entities(
    request: Request,
    kind: str | None = Query(None, pattern="^(user|host|ip)$"),
    min_level: str = Query("LOW", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    limit: int = Query(50, ge=1, le=500),
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    """Top-risk entities (users / hosts / IPs) by accumulated score."""
    org = _scoped_org(request)
    manager = EntityRiskManager(db)
    rows = manager.leaderboard(org=org, kind=kind, limit=limit, min_level=min_level)
    if not include_demo:
        rows = [r for r in rows if not r.demo]
    return {
        "total": len(rows),
        "entities": [r.to_dict() for r in rows],
    }


@router.get("/entities/{kind}/{name}")
def rba_entity_profile(
    request: Request,
    kind: str,
    name: str,
    timeline_limit: int = Query(100, ge=1, le=500),
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    """One entity's accumulated risk plus its score timeline."""
    if kind not in ("user", "host", "ip"):
        raise HTTPException(400, "kind must be user, host or ip")
    org = _scoped_org(request)
    manager = EntityRiskManager(db)
    entity = manager.profile(kind, name, org=org)
    if entity is None:
        raise HTTPException(404, "Entity has no accumulated risk record")
    if entity.demo and not include_demo:
        raise HTTPException(404, "Entity has no accumulated risk record")
    timeline = manager.timeline(kind, name, org=org, limit=timeline_limit)
    if not include_demo:
        timeline = [e for e in timeline if not e.demo]
    return {
        "entity": entity.to_dict(),
        "timeline": [e.to_dict() for e in timeline],
    }


@router.get("/rules")
def rba_correlation_rules(db: Session = Depends(get_db)):
    """Declarative correlation rules currently loaded from YAML."""
    specs = load_correlation_rules()
    return {
        "total": len(specs),
        "rules": [s.to_dict() for s in specs],
    }


@router.post("/decay", dependencies=[Depends(require_admin)])
def rba_decay(
    request: Request,
    db: Session = Depends(get_db),
):
    """Apply the exponential decay pass to all entity scores (admin)."""
    manager = EntityRiskManager(db)
    decayed = manager.decay()
    db.commit()
    return {"decayed": decayed}


@router.post("/sync", dependencies=[Depends(require_admin)])
def rba_sync(
    request: Request,
    hours: int = Query(24, ge=1, le=24 * 30),
    db: Session = Depends(get_db),
):
    """Backfill entity risk from recent alerts and raise due notables."""
    org = _scoped_org(request)
    manager = EntityRiskManager(db)
    folded = manager.sweep_entities_from_events(hours=hours, org=org)
    notables = manager.escalate(org=org)
    db.commit()
    return {"folded_alerts": folded, "notables_created": len(notables)}


class TuningUpdate(BaseModel):
    """One or more runtime tuning keys to persist (see backend.detection.tuning)."""

    rule_risk_weights: dict[str, float] | None = Field(None)
    risk_thresholds: dict[str, float] | None = Field(None)
    risk_decay_days: float | None = Field(None, gt=0)
    risk_notable_window_hours: float | None = Field(None, gt=0)
    entity_risk_enabled: bool | None = Field(None)


@router.get("/tuning")
def rba_get_tuning(db: Session = Depends(get_db)):
    """Effective detection tuning (env defaults merged with DB overrides)."""
    return get_tuning(db)


@router.put("/tuning", dependencies=[Depends(require_admin)])
def rba_update_tuning(
    body: TuningUpdate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Persist runtime tuning (risk weights, thresholds, decay) as admin.

    Changes apply immediately: the next accumulation / decay / escalation
    pass reads the new values.
    """
    who = actor_name(request) or "admin"
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "no tuning values provided")
    for key, value in updates.items():
        try:
            set_tuning(db, key, value, updated_by=who)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
    return get_tuning(db)
