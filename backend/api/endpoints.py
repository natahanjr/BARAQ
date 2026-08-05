"""Multi-endpoint ingest + fleet status API.

Remote SentinelSOC agents POST collected telemetry to :func:`ingest`, which
attributes every record to the reporting host and pushes it through the
standard pipeline. Endpoint rows track per-host volume and last-seen so the
dashboard can show an endpoint fleet at a glance.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.system import run_pipeline
from backend.config import AGENT_KEYS
from backend.database.connection import get_db
from backend.database.models import Endpoint
from backend.security import require_auth

logger = logging.getLogger("sentinel.api.endpoints")
router = APIRouter(
    prefix="/api",
    tags=["endpoints"],
    dependencies=[Depends(require_auth)],
)

AGENT_KEY_HEADER = "X-Agent-Key"


class IngestRequest(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=2000)
    host: str = Field(default="", max_length=128)
    agent_id: str = Field(default="", max_length=64)


@router.post("/ingest")
def ingest(
    body: IngestRequest,
    x_agent_key: str | None = Header(default=None, alias=AGENT_KEY_HEADER),
    db: Session = Depends(get_db),
):
    """Agent intake: validate key, tag host, run the full pipeline."""
    agent_id = AGENT_KEYS.get((x_agent_key or "").strip())
    if not agent_id:
        raise HTTPException(401, "Missing or invalid agent key (X-Agent-Key header)")

    host = (body.host or agent_id)[:128]
    for record in body.records:
        record["host"] = host

    try:
        result = run_pipeline(db, body.records)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ingest from agent %s failed", agent_id)
        raise HTTPException(500, f"Ingest pipeline failed: {exc}")

    endpoint = db.get(Endpoint, agent_id)
    if endpoint is None:
        endpoint = Endpoint(
            agent_id=agent_id,
            host=host,
            records_total=0,
            events_total=0,
            alerts_total=0,
        )
        db.add(endpoint)
    endpoint.host = host
    endpoint.last_seen = datetime.now(timezone.utc)
    endpoint.records_total += len(body.records)
    endpoint.events_total += result["saved_events"]
    endpoint.alerts_total += result["alerts_created"]
    db.commit()

    logger.info(
        "Agent %s (%s) ingested %d records -> %d alerts",
        agent_id, host, len(body.records), result["alerts_created"],
    )
    return {"agent_id": agent_id, "host": host, **result}


@router.get("/endpoints")
def list_endpoints(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(Endpoint).order_by(Endpoint.last_seen.desc()).limit(limit)
    ).all()
    return {"items": [ep.to_dict() for ep in rows], "total": len(rows)}