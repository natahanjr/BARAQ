"""Multi-endpoint ingest + fleet status + remote agent control API.

Remote BARAQ agents POST collected telemetry to :func:`ingest`, which
attributes every record to the reporting host and pushes it through the
standard pipeline. Endpoint rows track per-host volume and last-seen so the
dashboard can show an endpoint fleet at a glance.

The same channel carries remote agent control: analysts queue commands
(block_ip / kill_process / quarantine / escalate) for an agent; the agent
polls ``GET /api/commands/pending`` on its next cycle, executes them and
reports the outcome to ``POST /api/commands/{id}/result``.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from enum import Enum

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.api.system import run_pipeline
from backend.audit import client_ip, log_action
from backend.config import AGENT_KEYS, agent_org
from backend.database.connection import get_db
from backend.database.models import AgentCommand, Endpoint, NormalizedEvent, Verdict
from backend.security import actor_name, tenant_scope, require_admin, require_auth

logger = logging.getLogger("baraq.api.endpoints")
router = APIRouter(
    prefix="/api",
    tags=["endpoints"],
)

AGENT_KEY_HEADER = "X-Agent-Key"

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def require_agent(
    x_agent_key: str | None = Header(default=None, alias=AGENT_KEY_HEADER),
) -> str:
    """Resolve the calling agent's id from the X-Agent-Key header."""
    agent_id = AGENT_KEYS.get((x_agent_key or "").strip())
    if not agent_id:
        raise HTTPException(401, "Missing or invalid agent key (X-Agent-Key header)")
    return agent_id


class IngestRequest(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=2000)
    host: str = Field(default="", max_length=128)
    agent_id: str = Field(default="", max_length=64)


def _validate_ingest_records(records: list[dict]) -> None:
    """Reject malformed agent records with a 400 before they reach the pipeline.

    The normalizer coerces ``event_id`` to int, so a non-numeric value would
    otherwise bubble up as an unhelpful 500.
    """
    for idx, record in enumerate(records):
        if not isinstance(record, dict):
            raise HTTPException(400, f"record[{idx}] must be an object")
        event_id = record.get("event_id", 0)
        if not isinstance(event_id, int) and not str(event_id).isdigit():
            raise HTTPException(
                400,
                f"record[{idx}].event_id must be numeric, got {event_id!r}",
            )
        if not str(record.get("source", "")).strip():
            raise HTTPException(400, f"record[{idx}] missing source")
        if not str(record.get("timestamp", "")).strip():
            raise HTTPException(400, f"record[{idx}] missing timestamp")


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

    _validate_ingest_records(body.records)
    host = (body.host or agent_id)[:128]
    org = agent_org(agent_id)
    for record in body.records:
        record["host"] = host

    try:
        result = run_pipeline(db, body.records, org=org)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Ingest from agent %s failed", agent_id)
        raise HTTPException(500, f"Ingest pipeline failed: {exc}")

    endpoint = db.get(Endpoint, agent_id)
    if endpoint is None:
        endpoint = Endpoint(
            agent_id=agent_id,
            host=host,
            org=org,
            records_total=0,
            events_total=0,
            alerts_total=0,
        )
        db.add(endpoint)
    endpoint.host = host
    endpoint.org = org
    endpoint.last_seen = datetime.now(timezone.utc)
    endpoint.records_total += len(body.records)
    endpoint.events_total += result["saved_events"]
    endpoint.alerts_total += result["alerts_created"]
    db.commit()

    logger.info(
        "Agent %s (%s) org=%s ingested %d records -> %d alerts",
        agent_id, host, org or "(system)", len(body.records), result["alerts_created"],
    )
    return {"agent_id": agent_id, "host": host, "org": org, **result}


@router.get("/endpoints", dependencies=[Depends(require_auth)])
def list_endpoints(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Endpoint)
    if scope is not None:
        stmt = stmt.where(Endpoint.org == scope)
    rows = db.scalars(
        stmt.order_by(Endpoint.last_seen.desc()).limit(limit)
    ).all()
    return {"items": [ep.to_dict() for ep in rows], "total": len(rows)}


# ---------------------------------------------------------------------------
# Remote agent control
# ---------------------------------------------------------------------------


class CommandAction(str, Enum):
    block_ip = "block_ip"
    kill_process = "kill_process"
    quarantine = "quarantine"
    isolate = "isolate"
    disable_account = "disable_account"
    escalate = "escalate"


class CommandCreate(BaseModel):
    action: CommandAction
    target: str = Field("", max_length=256)
    note: str = Field("", max_length=500)


class CommandResult(BaseModel):
    status: str = Field("success", pattern="^(success|failed)$")
    detail: str = Field("", max_length=2000)


def _validate_target(action: str, target: str) -> str:
    if action == "block_ip" and not _IP_RE.match(target):
        raise HTTPException(422, "block_ip requires a valid IPv4 target")
    if action in ("kill_process", "quarantine") and not target.strip():
        raise HTTPException(422, f"{action} requires a target")
    return target.strip()


@router.post("/endpoints/{agent_id}/commands", dependencies=[Depends(require_admin)])
def queue_command(
    agent_id: str,
    body: CommandCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    if not db.get(Endpoint, agent_id):
        raise HTTPException(404, "Unknown agent - has it reported yet?")
    target = _validate_target(body.action.value, body.target)
    command = AgentCommand(
        agent_id=agent_id,
        action=body.action.value,
        target=target,
        status="pending",
        detail=body.note,
    )
    db.add(command)
    db.commit()
    log_action(db, actor_name(request), "command.queue", "agent", agent_id,
               f"{body.action.value} {target} -> command #{command.id}", client_ip(request))
    logger.info("Queued %s %s for agent %s (command #%s)", body.action.value, target, agent_id, command.id)
    return command.to_dict()


@router.get("/endpoints/{agent_id}/commands", dependencies=[Depends(require_auth)])
def list_agent_commands(
    agent_id: str,
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    if scope is not None and not db.scalar(
        select(Endpoint).where(Endpoint.agent_id == agent_id, Endpoint.org == scope)
    ):
        raise HTTPException(404, "Unknown agent")
    rows = db.scalars(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id)
        .order_by(AgentCommand.created_at.desc())
        .limit(limit)
    ).all()
    return {"agent_id": agent_id, "items": [c.to_dict() for c in rows]}


@router.get("/commands", dependencies=[Depends(require_auth)])
def list_commands(
    request: Request,
    status: str | None = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    stmt = select(AgentCommand)
    scope = tenant_scope(request)
    if scope is not None:
        stmt = stmt.where(
            AgentCommand.agent_id.in_(
                select(Endpoint.agent_id).where(Endpoint.org == scope)
            )
        )
    if status:
        stmt = stmt.where(AgentCommand.status == status)
    stmt = stmt.order_by(AgentCommand.created_at.desc()).limit(limit)
    rows = db.scalars(stmt).all()
    return {"items": [c.to_dict() for c in rows]}


@router.get("/commands/pending", dependencies=[Depends(require_agent)])
def pending_commands(agent_id: str = Depends(require_agent), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(AgentCommand)
        .where(AgentCommand.agent_id == agent_id, AgentCommand.status == "pending")
        .order_by(AgentCommand.created_at.asc())
        .limit(20)
    ).all()
    return {"items": [c.to_dict() for c in rows]}


@router.post("/commands/{command_id}/result", dependencies=[Depends(require_agent)])
def report_result(
    command_id: int,
    body: CommandResult,
    agent_id: str = Depends(require_agent),
    db: Session = Depends(get_db),
):
    command = db.get(AgentCommand, command_id)
    if not command or command.agent_id != agent_id:
        raise HTTPException(404, "Command not found for this agent")
    command.status = body.status
    command.detail = body.detail
    command.executed_at = datetime.now(timezone.utc)
    db.commit()
    logger.info("Agent %s executed command #%s -> %s", agent_id, command_id, body.status)
    return command.to_dict()


# =====================================================================
# Analyst feedback loop (ML ground truth)
# =====================================================================

class VerdictCreate(BaseModel):
    event_id: int = Field(..., ge=1)
    verdict: str = Field(...)  # true_positive | false_positive
    note: str = Field(default="", max_length=500)


@router.post("/ml/verdicts", dependencies=[Depends(require_admin)])
def record_verdict(
    body: VerdictCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Store an analyst verdict on a scored event (feedback ground truth).

    Upserts - a second verdict on the same event overwrites the first. The
    verdict becomes the authoritative training label for that event.
    """
    if body.verdict not in ("true_positive", "false_positive"):
        raise HTTPException(422, "verdict must be true_positive | false_positive")
    event = db.get(NormalizedEvent, body.event_id)
    if event is None:
        raise HTTPException(404, "No such event")
    row = db.scalars(
        select(Verdict).where(Verdict.event_id == body.event_id)
    ).first()
    if row is None:
        row = Verdict(
            event_id=body.event_id,
            verdict=body.verdict,
            note=body.note,
            created_by=actor_name(request),
        )
        db.add(row)
    else:
        row.verdict = body.verdict
        row.note = body.note or row.note
    db.commit()
    log_action(
        db, actor_name(request), "verdict.record",
        "event", body.event_id, f"{body.verdict} - {body.note or 'no note'}",
        client_ip(request),
    )
    return row.to_dict()


@router.get("/verdicts", dependencies=[Depends(require_auth)])
def list_verdicts(
    verdict: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    """List analyst verdicts (optionally filtered to one class)."""
    from backend.audit import client_ip  # noqa: F401  (unused helper guard)

    stmt = select(Verdict).order_by(Verdict.created_at.desc()).limit(limit)
    if verdict:
        stmt = (
            select(Verdict)
            .where(Verdict.verdict == verdict)
            .order_by(Verdict.created_at.desc())
            .limit(limit)
        )
    rows = db.scalars(stmt).all()
    event_ids = [v.event_id for v in rows]
    events = {
        e.id: e
        for e in db.scalars(
            select(NormalizedEvent).where(NormalizedEvent.id.in_(event_ids))
        )
    } if event_ids else {}
    items = []
    for v in rows:
        item = v.to_dict()
        ev = events.get(v.event_id)
        item["event_id"] = v.event_id
        item["event_type"] = ev.event_id if ev else None
        item["category"] = (ev.raw_json or {}).get("category") if ev else None
        item["risk_score"] = ev.risk_score if ev else None
        item["timestamp"] = ev.timestamp.isoformat() if (ev and ev.timestamp) else None
        items.append(item)
    return {"items": items, "total": len(items)}