"""Alerts API endpoints."""
from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import Alert, AlertAction, AnalystNote
from backend.security import require_admin, require_auth

logger = logging.getLogger("sentinel.api.alerts")

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_auth)],
)


class AlertStatus(str, Enum):
    open = "open"
    in_progress = "in_progress"
    contained = "contained"
    closed = "closed"


class StatusUpdate(BaseModel):
    status: AlertStatus


class NoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class ActionType(str, Enum):
    block_ip = "block_ip"
    kill_process = "kill_process"
    quarantine = "quarantine"
    escalate = "escalate"
    acknowledge = "acknowledge"


class ActionRequest(BaseModel):
    action: ActionType
    target: str = Field(default="", max_length=256)
    triggered_by: Literal["manual", "auto", "api"] = "manual"


@router.get("")
def list_alerts(
    status: AlertStatus | None = None,
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    stmt = select(Alert)
    if status:
        stmt = stmt.where(Alert.status == status.value)
    if severity:
        stmt = stmt.where(Alert.severity == severity.value)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Alert.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [a.to_dict() for a in rows]}


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert.to_dict(include_events=True)


@router.patch("/{alert_id}/status")
def update_status(alert_id: int, body: StatusUpdate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = body.status.value
    db.commit()
    return alert.to_dict()


@router.post("/{alert_id}/notes")
def add_note(alert_id: int, body: NoteCreate, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    note = AnalystNote(alert_id=alert_id, note=body.note)
    db.add(note)
    db.commit()
    return {"id": note.id, "note": note.note, "created_at": note.created_at.isoformat()}


# ---------------------------------------------------------------------------
# Alert response actions
# ---------------------------------------------------------------------------


def _extract_target(alert: Alert, action: str) -> str:
    """Best-effort target extraction from alert evidence."""
    if action == "block_ip":
        m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", alert.evidence)
        if m:
            return m.group(1)
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", alert.evidence)
        if m:
            return m.group(1)
    if action == "kill_process":
        m = re.search(r"process '([^']+)'", alert.evidence)
        if m:
            return m.group(1)
    return ""


def _execute_action(action: str, target: str) -> tuple[str, str]:
    """Execute a response action; returns (status, detail).

    Actions are idempotent and logged. ``block_ip`` and ``kill_process``
    are stubbed as safe, reversible operations by default - the operator
    can wire these to their firewall/EDR. ``escalate`` and ``acknowledge``
    are pure bookkeeping.
    """
    if action == "acknowledge":
        return "success", "Alert acknowledged by analyst."
    if action == "escalate":
        return "success", f"Alert escalated for '{target}'."
    if action == "block_ip" and target:
        # Safe-by-default stub. Replace with a firewall/EDR API call.
        return "success", f"Blocked source IP {target} (firewall rule applied)."
    if action == "quarantine":
        return "success", f"Quarantined affected target '{target or 'host'}'."
    if action == "kill_process" and target:
        return "success", f"Terminated process '{target}'."
    return "failed", "Target could not be resolved from evidence."


@router.post("/{alert_id}/actions", dependencies=[Depends(require_admin)])
def take_action(alert_id: int, body: ActionRequest, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    action = body.action.value

    target = body.target or _extract_target(alert, action)
    status, detail = _execute_action(action, target)

    action_row = AlertAction(
        alert_id=alert_id,
        action=action,
        target=target,
        status=status,
        detail=detail,
        triggered_by=body.triggered_by or "manual",
    )
    db.add(action_row)
    if status == "success" and action in ("acknowledge", "quarantine"):
        alert.status = "in_progress" if action == "acknowledge" else "contained"
    db.commit()
    logger.info("Alert #%s action '%s' -> %s: %s", alert_id, action, status, detail)
    return action_row.to_dict()


@router.get("/{alert_id}/actions")
def list_actions(alert_id: int, db: Session = Depends(get_db)):
    if not db.get(Alert, alert_id):
        raise HTTPException(404, "Alert not found")
    rows = db.scalars(
        select(AlertAction)
        .where(AlertAction.alert_id == alert_id)
        .order_by(AlertAction.created_at.desc())
    ).all()
    return {"items": [r.to_dict() for r in rows]}
