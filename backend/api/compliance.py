"""Compliance endpoints (roadmap 3.3): anonymized exports, DSAR, audit
retention, compliance report. All admin-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.audit import client_ip, log_action
from backend.database.connection import get_db
from backend.security import actor_name, require_admin, require_auth

router = APIRouter(
    prefix="/api/compliance",
    tags=["compliance"],
    dependencies=[Depends(require_auth)],
)


@router.get("/export", dependencies=[Depends(require_admin)])
def anonymized_export_endpoint(
    hours: int = Query(24, ge=0, le=720),
    org: str = Query("", max_length=64),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Anonymized (PII-masked) telemetry + alert export for a window."""
    from backend.compliance import anonymized_export

    try:
        data = anonymized_export(db, hours=hours, org=org)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    log_action(
        db,
        actor_name(request),
        "compliance.export",
        "dataset",
        f"{hours}h",
        f"anonymized export for org '{org}'",
        client_ip(request),
    )
    return data


@router.get("/dsar", dependencies=[Depends(require_admin)])
def dsar_endpoint(
    email: str = Query(..., min_length=2, max_length=128),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Data subject access request: everything stored about one person."""
    from backend.compliance import dsar_package

    try:
        data = dsar_package(db, email)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    log_action(
        db,
        actor_name(request),
        "compliance.dsar",
        "subject",
        email,
        "data subject access request",
        client_ip(request),
    )
    return data


@router.get("/report", dependencies=[Depends(require_admin)])
def compliance_report_endpoint(
    framework: str = Query("", description="SOC2, ISO27001, or NIST-CSF"),
    request: Request = None,
    db: Session = Depends(get_db),
):
    """Framework gap analysis or GDPR Art.30 data inventory."""
    if framework:
        from backend.compliance.gap_analysis import analyze_gaps
        from backend.compliance.frameworks import get_framework

        report = analyze_gaps(framework.upper())
        if not report:
            raise HTTPException(400, f"Unknown framework: {framework}")
        log_action(
            db,
            actor_name(request),
            "compliance.gap_report",
            "framework",
            framework,
            f"gap report for {framework}",
            client_ip(request),
        )
        controls = []
        for gap in report.gaps:
            controls.append({
                "id": gap.control_id,
                "control": gap.title,
                "status": gap.status,
                "gap": gap.gap_description,
                "remediation": gap.remediation,
            })
        for ctrl in get_framework(framework.upper()).controls:
            if ctrl.status == "compliant":
                controls.append({
                    "id": ctrl.control_id,
                    "control": ctrl.title,
                    "status": "compliant",
                    "gap": "",
                    "remediation": "",
                })
        return {
            "framework": report.framework,
            "total_controls": report.total_controls,
            "compliant": report.compliant,
            "partial": report.partial,
            "non_compliant": report.non_compliant,
            "unassessed": report.unassessed,
            "compliance_pct": report.compliance_pct,
            "controls": controls,
        }

    from backend.compliance import compliance_report

    report = compliance_report(db)
    log_action(
        db,
        actor_name(request),
        "compliance.report",
        "report",
        "",
        "compliance report generated",
        client_ip(request),
    )
    return report


@router.get("/audit/retention", dependencies=[Depends(require_admin)])
def audit_retention_status(db: Session = Depends(get_db)):
    """Audit trail age distribution vs the configured retention window."""
    from backend.audit import stats, verify_chain
    from backend.config import AUDIT_RETENTION_DAYS
    from backend.database.models import AuditLog

    oldest = db.scalar(select(func.min(AuditLog.created_at)))
    newest = db.scalar(select(func.max(AuditLog.created_at)))
    return {
        "retention_days": AUDIT_RETENTION_DAYS,
        "entries": stats(db)["total"],
        "oldest": oldest.isoformat() if oldest else None,
        "newest": newest.isoformat() if newest else None,
        "verify": verify_chain(db),
    }
