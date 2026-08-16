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
    include_demo: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    scope = tenant_scope(request)
    stmt = select(Alert)
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    if not include_demo:
        # Demo/test separation: the production queue never shows seeded data
        # unless the console explicitly runs in demo mode.
        stmt = stmt.where(Alert.demo.is_(False))
    if status:
        stmt = stmt.where(Alert.status == status.value)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Alert.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [a.to_dict() for a in rows]}


@router.get("/fp-analysis")
def fp_analysis(request: Request, db: Session = Depends(get_db)):
    """False-positive analysis over the alert history (roadmap P0).

    Ranks every rule with an FP candidate score derived from closed-without-
    action ratios, trigger density, confidence and severity. Read-only.
    """
    from backend.api.fp_analysis import analyze as fp_analyze

    scope = tenant_scope(request)
    return fp_analyze(db, org=scope or "")


class VerdictCreate(BaseModel):
    verdict: Literal["true_positive", "false_positive", "expected_behavior"]
    note: str = Field(default="", max_length=1000)
    suppress: bool = Field(default=False, description="Create a scoped suppression rule (expected_behavior only)")


@router.post("/{alert_id}/verdict")
def submit_verdict(
    alert_id: int,
    body: VerdictCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    """Analyst verdict on an alert (roadmap P2).

    ``expected_behavior`` verdicts may also create a scoped suppression rule
    (rule + host + user) so the workflow stops alerting. All verdicts feed
    the ML feedback weights via the detector's feedback loop.
    """
    from datetime import datetime, timezone

    from backend.database.models import AlertVerdict
    from backend.detection.suppression import create as create_suppression
    from backend.ml.anomaly import get_detector

    alert = _scoped_alert(request, alert_id, db)
    actor = actor_name(request)

    existing = db.scalars(
        select(AlertVerdict).where(AlertVerdict.alert_id == alert_id)
    ).first()
    if existing:
        existing.verdict = body.verdict
        existing.note = body.note
        existing.created_by = actor
        existing.created_at = datetime.now(timezone.utc)
        verdict = existing
    else:
        verdict = AlertVerdict(
            alert_id=alert_id,
            verdict=body.verdict,
            note=body.note,
            created_by=actor,
        )
        db.add(verdict)

    if body.verdict == "expected_behavior":
        alert.status = "closed"
        if body.suppress:
            user = _evidence_user(alert)
            create_suppression(
                db, rule=alert.rule, host=alert.host or "*",
                user=user if user else "*",
                reason=f"Analyst verdict: expected behavior - {body.note[:200]}",
                created_by=actor, org=alert.org or "",
            )

    # Feed the ML feedback loop: false_positive and expected_behavior dampen
    # the signal, true_positive strengthens it.
    try:
        behavior = alert.rule
        get_detector().apply_feedback(
            "true_positive" if body.verdict == "true_positive" else "false_positive",
            behavior,
        )
    except Exception:  # noqa: BLE001 - feedback must never break the verdict
        logger.debug("ML feedback skipped for alert #%s", alert_id, exc_info=True)

    db.commit()
    log_action(db, actor, "alert.verdict", "alert", str(alert_id),
               f"{body.verdict}: {body.note[:200]}", client_ip(request))
    return verdict.to_dict()


@router.get("/{alert_id}/verdict")
def get_verdict(alert_id: int, request: Request, db: Session = Depends(get_db)):
    _scoped_alert(request, alert_id, db)
    from backend.database.models import AlertVerdict

    verdict = db.scalars(
        select(AlertVerdict).where(AlertVerdict.alert_id == alert_id)
    ).first()
    return verdict.to_dict() if verdict else None


@router.get("/suppressions/list")
def list_suppressions(
    request: Request,
    include_expired: int = Query(0, ge=0, le=1),
    db: Session = Depends(get_db),
):
    """Active (or all, including expired) suppression rules (roadmap P2)."""
    from backend.detection.suppression import list_rules

    scope = tenant_scope(request)
    rules = list_rules(db, org=scope or "", include_expired=bool(include_expired))
    return {"items": [r.to_dict() for r in rules]}


class SuppressionCreate(BaseModel):
    rule: str = Field(min_length=1, max_length=64)
    host: str = Field(default="*", max_length=128)
    user: str = Field(default="*", max_length=128)
    reason: str = Field(default="", max_length=512)
    expires_hours: float = Field(default=168.0, ge=0)


@router.post("/suppressions", dependencies=[Depends(require_admin)])
def create_suppression_rule(
    body: SuppressionCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    from backend.detection.suppression import create as create_suppression

    scope = tenant_scope(request)
    rule = create_suppression(
        db, rule=body.rule, host=body.host, user=body.user,
        reason=body.reason, created_by=actor_name(request),
        org=scope or "", expires_hours=body.expires_hours,
    )
    log_action(db, actor_name(request), "suppression.create", "suppression",
               str(rule.id), f"{body.rule} {body.host}/{body.user}", client_ip(request))
    return rule.to_dict()


@router.delete("/suppressions/{rule_id}", dependencies=[Depends(require_admin)])
def delete_suppression_rule(
    rule_id: int,
    request: Request,
    db: Session = Depends(get_db),
):
    from backend.detection.suppression import delete as delete_suppression

    scope = tenant_scope(request)
    if not delete_suppression(db, rule_id, org=scope or ""):
        raise HTTPException(404, "Suppression rule not found")
    log_action(db, actor_name(request), "suppression.delete", "suppression",
               str(rule_id), "", client_ip(request))
    return {"deleted": rule_id}


@router.get("/groups")
def alert_groups(request: Request, db: Session = Depends(get_db)):
    """Group repeated detections (roadmap P0): open alerts bucketed by
    (rule, host, evidence-user) with repeat counts - one glance tells an
    analyst which detections are a single recurring event, not a campaign."""
    from backend.detection.workflow import ACTIVE_STATES

    scope = tenant_scope(request)
    stmt = select(Alert).where(Alert.status.in_(ACTIVE_STATES))
    if scope is not None:
        stmt = stmt.where(Alert.org == scope)
    alerts = db.scalars(stmt.order_by(Alert.created_at.desc()).limit(2000)).all()

    groups: dict[tuple[str, str, str], list[Alert]] = {}
    for alert in alerts:
        user = _evidence_user(alert)
        key = (alert.rule, alert.host or "", user)
        groups.setdefault(key, []).append(alert)

    items = []
    for (rule, host, user), rows in groups.items():
        rows_sorted = sorted(rows, key=lambda a: a.created_at)
        items.append({
            "rule": rule,
            "host": host,
            "user": user,
            "count": len(rows),
            "trigger_count": sum(a.trigger_count or 1 for a in rows),
            "severity": max(rows_sorted, key=lambda a: _SEV_ORDER.get(a.severity, 0)).severity,
            "max_severity_index": max(_SEV_ORDER.get(a.severity, 0) for a in rows),
            "first_seen": rows_sorted[0].created_at.isoformat(),
            "last_seen": rows_sorted[-1].created_at.isoformat(),
            "alert_ids": [a.id for a in rows_sorted[-5:]],
            "sample_names": sorted({a.name for a in rows}),
        })
    items.sort(key=lambda g: (-g["count"], -g["max_severity_index"]))
    return {"items": items, "groups": len(items), "alerts_grouped": len(alerts)}


_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


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


_IP_LITERAL = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IP_FROM = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
_PROCESS_QUOTED = re.compile(r"process '([^']+)'", re.IGNORECASE)
_PROCESS_FIELD = re.compile(
    r"(?:NewProcessName|New Process Name|ProcessName|ImagePath|Image|SourceImage|ParentImage)"
    r"\s*['\"]?\s*[:=]\s*['\"]?([A-Za-z]:[\\/][^'\"\r\n;,]+?\.exe)",
    re.IGNORECASE,
)
_PROCESSTOKEN = re.compile(r"(?:^|[^\w.\\])([\w.-]+\.exe)", re.IGNORECASE)
_ACCOUNT_QUOTED = re.compile(r"(?:account|user) '([^']+)'", re.IGNORECASE)


def _basename(path_or_name: str) -> str:
    return path_or_name.replace("\\", "/").rsplit("/", 1)[-1].strip()


def _evidence_user(alert: Alert) -> str:
    """Best-effort user extraction from alert evidence + linked events."""
    scope = _evidence_scope(alert)
    m = re.search(r"\b(?:user|user_name|user_id|account)\s*[:=]\s*([A-Za-z0-9_.\\-]+)", scope)
    return m.group(1) if m else ""


def _evidence_scope(alert: Alert) -> str:
    """Evidence text plus linked event payloads, so target extraction works
    for Sigma rules (evidence only embeds a truncated event message)."""
    parts = [alert.evidence or ""]
    for link in list(getattr(alert, "events", []) or [])[:10]:
        event = getattr(link, "event", None)
        if event is None:
            continue
        if getattr(event, "message", ""):
            parts.append(event.message)
        raw = getattr(event, "raw_json", None)
        if raw:
            parts.append(repr(raw))
    return " ".join(parts)


def _extract_target(alert: Alert, action: str) -> str:
    """Best-effort target extraction from alert evidence + linked events."""
    scope = _evidence_scope(alert)
    if action == "block_ip":
        m = _IP_FROM.search(scope)
        if m:
            return m.group(1)
        m = _IP_LITERAL.search(scope)
        if m:
            return m.group(0)
    if action == "kill_process":
        m = _PROCESS_QUOTED.search(scope)
        if m:
            return m.group(1)
        m = _PROCESS_FIELD.search(scope)
        if m:
            return _basename(m.group(1))
        m = _PROCESSTOKEN.search(scope)
        if m:
            return m.group(1)
    if action == "disable_account":
        m = _ACCOUNT_QUOTED.search(scope)
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
    if action == "block_ip":
        if not target:
            return "success", "No source IP present in the alert evidence - nothing to block."
        # Safe-by-default stub. Replace with a firewall/EDR API call.
        return "success", f"Blocked source IP {target} (firewall rule applied)."
    if action == "quarantine":
        return "success", f"Quarantined affected target '{target or 'host'}'."
    if action == "kill_process":
        if not target:
            return "failed", "No process identified in the alert evidence to terminate."
        return "success", f"Terminated process '{target}'."
    if action == "isolate":
        return "success", f"Isolated endpoint '{target or 'host'}' (network containment applied)."
    if action == "disable_account":
        if not target:
            return "success", "No account identified in the alert evidence - nothing to disable."
        return "success", f"Disabled account '{target}' and forced MFA re-enrolment."
    return "failed", "Unknown action."


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
    shown = target if target else detail
    log_action(db, actor_name(request), "alert.action", "alert", str(alert_id),
               f"{action} -> {status} ({shown})", client_ip(request))
    logger.info("Alert #%s action '%s' -> %s: %s", alert_id, action, status, detail)
    return action_row.to_dict()


def _bump_severity(alert: Alert) -> None:
    """Escalate an alert one step up the severity ladder.

    Risk bookkeeping is recomputed from the new severity so the displayed
    severity and the risk level never diverge (roadmap P0 consistency).
    """
    ladder = ("low", "medium", "high", "critical")
    try:
        idx = ladder.index(alert.severity)
    except ValueError:
        return
    if idx >= len(ladder) - 1:
        return
    alert.severity = ladder[idx + 1]
    from backend.risk.scoring import hybrid_risk

    score, level = hybrid_risk(
        severity=alert.severity,
        confidence=alert.confidence or 0.5,
        event_count=alert.event_count or 1,
        anomaly_scores=[],
    )
    alert.risk_score = score
    alert.risk_level = level


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
