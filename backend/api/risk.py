"""Phase 6 risk API (spec 6.46-6.48, 6.53, 6.65, 6.77).

Read-oriented surface: list (with filters), detail, per-entity lookup,
factors, timeline, graph, audit, explain, metrics, health, ranking and
evaluation. The only mutation is the operator-triggered recalculation
(6.65). Gated by ``RISK_ENABLED`` (PEP 562) and inert against the
production database.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend import config
from backend.database.connection import get_db
from backend.risk import engine
from backend.risk import metrics as metrics_module
from backend.risk.calculator import calculate_risk, utcnow
from backend.risk.contract import (
    ENTITY_TYPES,
    RISK_SEVERITIES,
    RISK_STATES,
    RISK_TRENDS,
)
from backend.risk.evaluation import run_evaluation
from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
    EntityRiskV2Snapshot,
)
from backend.risk.registry import list_factors
from backend.security import require_auth


def __getattr__(name: str):
    """Expose the risk gate dynamically (PEP 562)."""
    if name == "RISK_ENABLED":
        return config.RISK_ENABLED
    raise AttributeError(name)


router = APIRouter(
    prefix="/api/risk",
    tags=["risk"],
    dependencies=[Depends(require_auth)],
)


def _gate() -> None:
    if not config.RISK_ENABLED:
        raise HTTPException(status_code=404, detail="risk intelligence is disabled")


def _fetch(db: Session, risk_id: str) -> EntityRiskV2:
    row = db.scalars(
        select(EntityRiskV2).where(EntityRiskV2.risk_id == risk_id)
    ).first()
    if row is None:
        raise HTTPException(status_code=404, detail=f"unknown risk {risk_id}")
    return row


def _related_entities(db: Session, risk: EntityRiskV2) -> list[dict]:
    """Contextual neighbours of an entity (spec 6.48, 6.80): entities the
    risk received propagation from (incoming) or passed context to
    (outgoing), with the relationship type and direct/contextual origin."""
    label = f"{risk.entity_type}:{risk.entity_id}"
    related: list[dict] = []

    incoming = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.risk_id == risk.risk_id,
            EntityRiskV2Factor.propagation_from.is_not(None),
        )
    ).all()
    for row in incoming:
        parts = (row.propagation_from or "").split(":", 1)
        if len(parts) == 2:
            related.append(
                {
                    "entity_type": parts[0],
                    "entity_id": parts[1],
                    "relationship_type": row.relationship_type,
                    "direction": "incoming",
                    "origin": row.origin,
                    "factor_id": row.factor_id,
                }
            )

    outgoing = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.propagation_from == label,
            EntityRiskV2Factor.risk_id != risk.risk_id,
        )
    ).all()
    for row in outgoing:
        target = db.scalars(
            select(EntityRiskV2).where(EntityRiskV2.risk_id == row.risk_id)
        ).first()
        if target is not None:
            related.append(
                {
                    "entity_type": target.entity_type,
                    "entity_id": target.entity_id,
                    "relationship_type": row.relationship_type,
                    "direction": "outgoing",
                    "origin": row.origin,
                    "factor_id": row.factor_id,
                }
            )
    return related


@router.get("")
def list_risks(
    db: Session = Depends(get_db),
    entity_type: str | None = Query(default=None),
    entity_id: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    state: str | None = Query(default=None),
    score_min: float | None = Query(default=None, ge=0.0, le=100.0),
    score_max: float | None = Query(default=None, ge=0.0, le=100.0),
    trend: str | None = Query(default=None),
    first_seen_after: datetime | None = Query(default=None),
    last_seen_before: datetime | None = Query(default=None),
    factor_type: str | None = Query(default=None),
    source_type: str | None = Query(default=None),
) -> dict:
    """Entity risk list with every filter from spec 6.47."""
    _gate()
    stmt = select(EntityRiskV2).order_by(EntityRiskV2.id)
    if entity_type is not None:
        if entity_type not in ENTITY_TYPES:
            raise HTTPException(
                status_code=422, detail=f"invalid entity_type {entity_type!r}"
            )
        stmt = stmt.where(EntityRiskV2.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(EntityRiskV2.entity_id == entity_id)
    if severity is not None:
        if severity.upper() not in RISK_SEVERITIES:
            raise HTTPException(
                status_code=422, detail=f"invalid severity {severity!r}"
            )
        stmt = stmt.where(EntityRiskV2.severity == severity.upper())
    if state is not None:
        if state.upper() not in RISK_STATES:
            raise HTTPException(status_code=422, detail=f"invalid state {state!r}")
        stmt = stmt.where(EntityRiskV2.state == state.upper())
    if score_min is not None:
        stmt = stmt.where(EntityRiskV2.score >= score_min)
    if score_max is not None:
        stmt = stmt.where(EntityRiskV2.score <= score_max)
    if trend is not None:
        if trend.upper() not in RISK_TRENDS:
            raise HTTPException(status_code=422, detail=f"invalid trend {trend!r}")
        stmt = stmt.where(EntityRiskV2.trend == trend.upper())
    if first_seen_after is not None:
        stmt = stmt.where(EntityRiskV2.first_seen >= first_seen_after)
    if last_seen_before is not None:
        stmt = stmt.where(EntityRiskV2.last_seen <= last_seen_before)
    if factor_type is not None:
        stmt = stmt.where(
            EntityRiskV2.risk_id.in_(
                select(EntityRiskV2Factor.risk_id).where(
                    EntityRiskV2Factor.factor_type == factor_type
                )
            )
        )
    if source_type is not None:
        stmt = stmt.where(
            EntityRiskV2.risk_id.in_(
                select(EntityRiskV2Factor.risk_id).where(
                    EntityRiskV2Factor.source_type == source_type
                )
            )
        )
    rows = db.scalars(stmt).all()
    return {
        "count": len(rows),
        "risks": [row.to_dict() for row in rows],
    }


@router.get("/ranking/top")
def ranking(
    db: Session = Depends(get_db),
    kind: str = Query(default="hosts"),
    limit: int = Query(default=10, ge=1, le=100),
) -> dict:
    """Ranking (spec 6.53): top hosts/users/source IPs, fastest rising,
    recently escalated."""
    _gate()
    valid = ("hosts", "users", "source_ips", "rising", "escalated")
    if kind not in valid:
        raise HTTPException(status_code=422, detail=f"invalid ranking kind {kind!r}")
    if kind == "hosts":
        rows = db.scalars(
            select(EntityRiskV2)
            .where(EntityRiskV2.entity_type == "HOST", EntityRiskV2.score > 0)
            .order_by(EntityRiskV2.score.desc(), EntityRiskV2.risk_id)
            .limit(limit)
        ).all()
    elif kind == "users":
        rows = db.scalars(
            select(EntityRiskV2)
            .where(EntityRiskV2.entity_type == "USER", EntityRiskV2.score > 0)
            .order_by(EntityRiskV2.score.desc(), EntityRiskV2.risk_id)
            .limit(limit)
        ).all()
    elif kind == "source_ips":
        rows = db.scalars(
            select(EntityRiskV2)
            .where(EntityRiskV2.entity_type == "SOURCE_IP", EntityRiskV2.score > 0)
            .order_by(EntityRiskV2.score.desc(), EntityRiskV2.risk_id)
            .limit(limit)
        ).all()
    elif kind == "rising":
        rows = db.scalars(
            select(EntityRiskV2)
            .where(EntityRiskV2.trend == "RISING", EntityRiskV2.score > 0)
            .order_by(EntityRiskV2.score.desc(), EntityRiskV2.risk_id)
            .limit(limit)
        ).all()
    else:
        rows = db.scalars(
            select(EntityRiskV2)
            .where(
                EntityRiskV2.severity.in_(("HIGH", "CRITICAL")), EntityRiskV2.score > 0
            )
            .order_by(EntityRiskV2.updated_at.desc(), EntityRiskV2.risk_id)
            .limit(limit)
        ).all()
    return {
        "kind": kind,
        "count": len(rows),
        "entities": [row.to_dict() for row in rows],
    }


@router.get("/metrics/health")
def risk_health(db: Session = Depends(get_db)) -> dict:
    """Risk health (spec 6.77): calculations, failures, latency, factors."""
    _gate()
    metrics = metrics_module.risk_metrics(db)
    failures = db.scalars(
        select(func.count())
        .select_from(EntityRiskV2AuditEvent)
        .where(EntityRiskV2AuditEvent.action == "RISK_CALCULATION_FAILED")
    ).one()
    return {
        "healthy": metrics["stale_entities"] == 0 and metrics["total_entities"] > 0,
        "total_entities": metrics["total_entities"],
        "stale_entities": metrics["stale_entities"],
        "calculations": metrics["risk_calculations"],
        "failures": failures,
        "p95_ms": metrics["calculation_latency"]["p95_ms"],
        "factors": sum(metrics["factor_distribution"].values()),
        "model_version": config.RISK_MODEL_VERSION,
        "last_calculation_at": metrics["as_of"],
    }


@router.get("/metrics")
def risk_metrics(db: Session = Depends(get_db)) -> dict:
    """Aggregate metrics (spec 6.55)."""
    _gate()
    return metrics_module.risk_metrics(db)


@router.get("/evaluation")
def evaluation(db: Session = Depends(get_db)) -> dict:
    """Labeled corpus counts (spec 6.57)."""
    _gate()
    return run_evaluation(db)


@router.get("/factors/registry")
def factor_registry() -> dict:
    """Registered factors (spec 6.41)."""
    _gate()
    return {"count": len(list_factors()), "factors": list_factors()}


@router.get("/{risk_id}")
def risk_detail(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Risk detail with contextual related entities (spec 6.48)."""
    _gate()
    row = _fetch(db, risk_id)
    payload = row.to_dict()
    payload["related_entities"] = _related_entities(db, row)
    return payload


@router.get("/entity/{entity_type}/{entity_id}")
def entity_risk(
    entity_type: str, entity_id: str, db: Session = Depends(get_db)
) -> dict:
    """Risk record for one entity (spec 6.46)."""
    _gate()
    if entity_type not in ENTITY_TYPES:
        raise HTTPException(
            status_code=422, detail=f"invalid entity_type {entity_type!r}"
        )
    row = engine.risk_for_entity(db, entity_type, entity_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail=f"no risk record for {entity_type} {entity_id}",
        )
    payload = row.to_dict()
    payload["related_entities"] = _related_entities(db, row)
    return payload


@router.get("/{risk_id}/factors")
def risk_factors(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Every contribution with provenance (spec 6.42)."""
    _gate()
    _fetch(db, risk_id)
    rows = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk_id)
        .order_by(EntityRiskV2Factor.id)
    ).all()
    return {
        "risk_id": risk_id,
        "count": len(rows),
        "factors": [
            {
                "factor_id": row.factor_id,
                "factor_type": row.factor_type,
                "factor_version": row.factor_version,
                "source_type": row.source_type,
                "source_id": row.source_id,
                "value": row.value,
                "weight": row.weight,
                "contribution": row.contribution,
                "reason": row.reason,
                "evidence": row.evidence,
                "origin": row.origin,
                "propagation_from": row.propagation_from,
                "relationship_type": row.relationship_type,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                "expired_at": row.expired_at.isoformat() if row.expired_at else None,
            }
            for row in rows
        ],
    }


@router.get("/{risk_id}/explain")
def explain_risk(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """'Why is this entity high risk?' - full decomposition (6.32, 6.88)."""
    _gate()
    risk = _fetch(db, risk_id)
    rows = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk_id)
        .order_by(EntityRiskV2Factor.id)
    ).all()
    now = risk.last_calculated_at or utcnow()
    factors = [
        {
            "factor_id": row.factor_id,
            "factor_type": row.factor_type,
            "source_type": row.source_type,
            "source_id": row.source_id,
            "value": row.value,
            "weight": row.weight,
            "origin": row.origin,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
            "reason": row.reason,
            "evidence": row.evidence,
        }
        for row in rows
    ]
    calculation = calculate_risk(factors, now)
    explanation = [
        {
            "factor_id": c["factor_id"],
            "factor_type": c["factor_type"],
            "source_type": c["source_type"],
            "source_id": c["source_id"],
            "origin": c["origin"],
            "value": c["value"],
            "decay_factor": c["decay_factor"],
            "contribution": c["contribution"],
            "expired": c["expired"],
            "reason": c["reason"],
        }
        for c in calculation.factor_contributions
    ]
    return {
        "risk_id": risk_id,
        "entity_type": risk.entity_type,
        "entity_id": risk.entity_id,
        "score": calculation.final_score,
        "severity": calculation.severity,
        "state": risk.state,
        "trend": risk.trend,
        "confidence": calculation.confidence,
        "base_score": calculation.base_score,
        "factor_contributions": explanation,
        "decay_adjustments": calculation.decay_adjustments,
        "propagation_adjustments": calculation.propagation_adjustments,
        "risk_model_version": calculation.risk_model_version,
        "calculated_at": now.isoformat(),
    }


@router.get("/{risk_id}/timeline")
def risk_timeline(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Score history from append-only snapshots (spec 6.23)."""
    _gate()
    _fetch(db, risk_id)
    rows = db.scalars(
        select(EntityRiskV2Snapshot)
        .where(EntityRiskV2Snapshot.risk_id == risk_id)
        .order_by(EntityRiskV2Snapshot.id)
    ).all()
    return {
        "risk_id": risk_id,
        "count": len(rows),
        "timeline": [
            {
                "score": row.score,
                "severity": row.severity,
                "state": row.state,
                "trend": row.trend,
                "factor_count": row.factor_count,
                "risk_model_version": row.risk_model_version,
                "captured_at": row.captured_at.isoformat() if row.captured_at else None,
            }
            for row in rows
        ],
    }


@router.get("/{risk_id}/graph")
def risk_graph(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Evidence graph: factors, sources and the entity (spec 6.46)."""
    _gate()
    risk = _fetch(db, risk_id)
    rows = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk_id)
        .order_by(EntityRiskV2Factor.id)
    ).all()
    nodes = [
        {
            "id": risk.risk_id,
            "kind": "ENTITY",
            "label": f"{risk.entity_type}:{risk.entity_id}",
            "score": risk.score,
        }
    ]
    edges: list[dict] = []
    for index, row in enumerate(rows):
        source_label = f"{row.source_type}:{row.source_id}"
        nodes.append(
            {
                "id": f"source-{index}",
                "kind": "SOURCE",
                "label": source_label,
                "factor": row.factor_id,
            }
        )
        edges.append(
            {
                "from": f"source-{index}",
                "to": risk.risk_id,
                "factor_id": row.factor_id,
                "contribution": row.contribution,
                "origin": row.origin,
            }
        )
    return {"risk_id": risk_id, "nodes": nodes, "edges": edges}


@router.get("/{risk_id}/audit")
def risk_audit(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Attribution trail (spec 6.44, 6.70)."""
    _gate()
    _fetch(db, risk_id)
    rows = db.scalars(
        select(EntityRiskV2AuditEvent)
        .where(EntityRiskV2AuditEvent.risk_id == risk_id)
        .order_by(EntityRiskV2AuditEvent.id)
    ).all()
    return {
        "risk_id": risk_id,
        "count": len(rows),
        "events": [
            {
                "action": row.action,
                "actor": row.actor,
                "details": row.details,
                "old_score": row.old_score,
                "new_score": row.new_score,
                "old_state": row.old_state,
                "new_state": row.new_state,
                "model_version": row.model_version,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


@router.post("/recalculate/{risk_id}")
def recalculate(risk_id: str, db: Session = Depends(get_db)) -> dict:
    """Operator-triggered recalculation (spec 6.65)."""
    _gate()
    _fetch(db, risk_id)
    return engine.manual_recalculate(db, risk_id)
