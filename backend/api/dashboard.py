"""Dashboard API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.database.connection import get_db
from backend.security import require_auth, tenant_scope

router = APIRouter(
    prefix="/api/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_auth)],
)


def _scope(request: Request) -> str | None:
    """Tenant scope for the caller: None = all orgs (admin), '' = system."""
    return tenant_scope(request)


@router.get("/summary")
def summary(request: Request, db: Session = Depends(get_db)):
    return dashboard.dashboard_summary(db, org=_scope(request))


@router.get("/timeline")
def timeline(
    request: Request,
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
):
    return {
        "events": dashboard.event_timeline(db, hours, org=_scope(request)),
        "alerts": dashboard.alert_timeline(db, hours, org=_scope(request)),
    }


@router.get("/threat-categories")
def threat_categories(request: Request, db: Session = Depends(get_db)):
    return dashboard.threat_categories(db, org=_scope(request))


@router.get("/severity-distribution")
def severity_distribution(request: Request, db: Session = Depends(get_db)):
    return dashboard.severity_distribution(db, org=_scope(request))


@router.get("/attack-stats")
def attack_stats(request: Request, db: Session = Depends(get_db)):
    return dashboard.attack_stats(db, org=_scope(request))


@router.get("/top-attackers")
def top_attackers(
    request: Request,
    limit: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
):
    return dashboard.top_attackers(db, limit, org=_scope(request))


@router.get("/user-behavior")
def user_behavior(
    request: Request,
    limit: int = Query(8, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return dashboard.user_behavior(db, limit, org=_scope(request))


@router.get("/detection-methods")
def detection_methods(request: Request, db: Session = Depends(get_db)):
    return dashboard.detection_method_breakdown(db, org=_scope(request))


@router.get("/risk-distribution")
def risk_distribution(request: Request, db: Session = Depends(get_db)):
    return dashboard.risk_distribution(db, org=_scope(request))