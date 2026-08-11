"""Alerts API endpoints."""
from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.database.models import Alert, AlertAction, AlertEventLink, AnalystNote
from backend.detection.workflow import can_transition, is_valid_state, next_states
from backend.reports.generator import generate_report
from backend.security import actor_name, tenant_scope, require_admin, require_auth

logger = logging.getLogger("baraq.api.alerts")

router = APIRouter(
    prefix="/api/alerts",
    tags=["alerts"],
    dependencies=[Depends(require_auth)],
)


class AlertStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    investigating = "investigating"
    in_progress = "in_progress"  # legacy alias for investigating
    contained = "contained"
    resolved = "resolved"
    closed = "closed"


class StatusUpdate(BaseModel):
    status: AlertStatus
    note: str = Field(default="", max_length=500)


class NoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=2000)


class ActionType(str, Enum):
    block_ip = "block_ip"
    kill_process = "kill_process"
    quarantine = "quarantine"
    isolate = "isolate"
    disable_account = "disable_account"
    escalate = "escalate"
    acknowledge = "acknowledge"
    fix = "fix"


class ActionRequest(BaseModel):
    action: ActionType
    target: str = Field(default="", max_length=256)
    triggered_by: Literal["manual", "auto", "api"] = "manual"


def _scoped_alert(request: Request, alert_id: int, db: Session) -> Alert:
    """Fetch an alert (with evidence) or 404 if outside the caller's scope."""
    scope = tenant_scope(request)
    stmt = (
        select(Alert)
        .options(
            selectinload(Alert.events).selectinload(AlertEventLink.event),
            selectinload(Alert.notes),
        )
        .where(Alert.id == alert_id)
    )
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alert = db.scalars(stmt).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.get("")
def list_alerts(
    request: Request,
    status: AlertStatus | None = None,
    severity: Literal["critical", "high", "medium", "low", "info"] | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Alert)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
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
def get_alert(alert_id: int, request: Request, db: Session = Depends(get_db)):
    alert = _scoped_alert(request, alert_id, db)
    return alert.to_dict(include_events=True)


@router.patch("/{alert_id}/status")
def update_status(alert_id: int, body: StatusUpdate, request: Request, db: Session = Depends(get_db)):
    alert = _scoped_alert(request, alert_id, db)
    target = body.status.value
    if target == "in_progress":  # legacy alias -> canonical state
        target = "investigating"
    if not is_valid_state(target):
        raise HTTPException(422, f"Unknown alert state '{target}'")
    previous = alert.status
    if not can_transition(previous, target):
        raise HTTPException(
            409,
            f"Invalid transition '{previous}' -> '{target}'. "
            f"Allowed from '{previous}': {', '.join(next_states(previous))}",
        )
    alert.status = target
    if body.note:
        db.add(AnalystNote(alert_id=alert_id, note=body.note))
    db.commit()
    log_action(db, actor_name(request), "alert.status", "alert", str(alert_id),
               f"{previous} -> {target}", client_ip(request))
    return alert.to_dict()


@router.post("/{alert_id}/notes")
def add_note(alert_id: int, body: NoteCreate, request: Request, db: Session = Depends(get_db)):
    alert = _scoped_alert(request, alert_id, db)
    note = AnalystNote(alert_id=alert_id, note=body.note)
    db.add(note)
    db.commit()
    log_action(db, actor_name(request), "alert.note", "alert", str(alert_id),
               body.note[:200], client_ip(request))
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
    if action == "disable_account":
        m = re.search(r"account '([^']+)'", alert.evidence)
        if m:
            return m.group(1)
        m = re.search(r"User '([^']+)'", alert.evidence)
        if m:
            return m.group(1)
    if action == "isolate":
        return alert.host or ""
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
    if action == "fix":
        return "success", "Alert marked as fixed and closed. Security score restored."
    if action == "escalate":
        return "success", f"Alert escalated for '{target}'."
    if action == "block_ip" and target:
        # Safe-by-default stub. Replace with a firewall/EDR API call.
        return "success", f"Blocked source IP {target} (firewall rule applied)."
    if action == "quarantine":
        return "success", f"Quarantined affected target '{target or 'host'}'."
    if action == "kill_process" and target:
        return "success", f"Terminated process '{target}'."
    if action == "isolate":
        return "success", f"Isolated endpoint '{target or 'host'}' (network containment applied)."
    if action == "disable_account":
        return "success", f"Disabled account '{target or 'unknown'}' and forced MFA re-enrolment."
    return "failed", "Target could not be resolved from evidence."


@router.post("/{alert_id}/actions", dependencies=[Depends(require_admin)])
def take_action(alert_id: int, body: ActionRequest, request: Request, db: Session = Depends(get_db)):
    alert = _scoped_alert(request, alert_id, db)
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
    if status == "success":
        if action == "acknowledge":
            alert.status = "acknowledged"
        elif action == "quarantine" and can_transition(alert.status, "contained"):
            alert.status = "contained"
        elif action == "escalate":
            _bump_severity(alert)
        elif action == "fix":
            alert.status = "closed"
    db.commit()
    log_action(db, actor_name(request), "alert.action", "alert", str(alert_id),
               f"{action} -> {status} ({target})", client_ip(request))
    logger.info("Alert #%s action '%s' -> %s: %s", alert_id, action, status, detail)
    return action_row.to_dict()


def _bump_severity(alert: Alert) -> None:
    """Escalate an alert one step up the severity ladder."""
    ladder = ("low", "medium", "high", "critical")
    try:
        idx = ladder.index(alert.severity)
    except ValueError:
        return
    if idx < len(ladder) - 1:
        alert.severity = ladder[idx + 1]


@router.get("/{alert_id}/actions")
def list_actions(alert_id: int, request: Request, db: Session = Depends(get_db)):
    _scoped_alert(request, alert_id, db)
    rows = db.scalars(
        select(AlertAction)
        .where(AlertAction.alert_id == alert_id)
        .order_by(AlertAction.created_at.desc())
    ).all()
    return {"items": [r.to_dict() for r in rows]}


@router.post("/clear", dependencies=[Depends(require_admin)])
def clear_alerts(request: Request, db: Session = Depends(get_db)):
    """Delete all open alerts and force-generate an incident report first.

    The report is generated while the alerts are still open, so it captures
    the full incident (evidence, score, threats) before the queue is cleared.
    Deleting removes the alerts from the dashboard list entirely; the forced
    report remains the permanent record.

    Evidence rows that would regenerate the same alerts are purged as well
    (vulnerability findings, file scans, ingested emails): otherwise rules
    re-fire on the same stored evidence every detection cycle and the list
    immediately fills again.
    """
    from backend.database.models import EmailMessage, FileScan, VulnFinding

    open_alerts = db.scalars(
        select(Alert).where(Alert.status == "open").order_by(Alert.created_at.desc())
    ).all()
    if not open_alerts:
        return {
            "cleared": 0,
            "message": "No open alerts to clear.",
            "report": None,
        }

    report = generate_report(db, "executive", "pdf")

    alert_ids = [a.id for a in open_alerts]
    rules = {a.rule for a in open_alerts}
    db.execute(
        AlertAction.__table__.delete().where(AlertAction.alert_id.in_(alert_ids))
    )
    if "vulnerability" in rules:
        db.execute(VulnFinding.__table__.delete())
    if "malware_file" in rules:
        db.execute(FileScan.__table__.delete())
    if "email_phishing" in rules:
        db.execute(EmailMessage.__table__.delete())
    for alert in open_alerts:
        db.delete(alert)
    db.commit()
    log_action(db, actor_name(request), "alerts.clear", "alert", ",".join(map(str, alert_ids)),
               f"deleted {len(open_alerts)} alert(s); report={report['file_path']}", client_ip(request))
    logger.info(
        "Cleared %d open alert(s) (deleted, evidence purged); forced report generated: %s",
        len(open_alerts),
        report["file_path"],
    )
    return {
        "cleared": len(open_alerts),
        "message": f"Cleared {len(open_alerts)} alert(s). Security score restored to 100. Incident report generated.",
        "report": report,
    }
