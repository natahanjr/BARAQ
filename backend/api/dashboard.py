"""Dashboard API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.analyzers import dashboard
from backend.database.connection import get_db

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db)):
    return dashboard.dashboard_summary(db)


@router.get("/timeline")
def timeline(hours: int = 24, db: Session = Depends(get_db)):
    return {
        "events": dashboard.event_timeline(db, hours),
        "alerts": dashboard.alert_timeline(db, hours),
    }


@router.get("/threat-categories")
def threat_categories(db: Session = Depends(get_db)):
    return dashboard.threat_categories(db)


@router.get("/severity-distribution")
def severity_distribution(db: Session = Depends(get_db)):
    return dashboard.severity_distribution(db)


@router.get("/attack-stats")
def attack_stats(db: Session = Depends(get_db)):
    return dashboard.attack_stats(db)


@router.get("/top-attackers")
def top_attackers(limit: int = 5, db: Session = Depends(get_db)):
    return dashboard.top_attackers(db, limit)


@router.get("/user-behavior")
def user_behavior(limit: int = 8, db: Session = Depends(get_db)):
    return dashboard.user_behavior(db, limit)


@router.get("/detection-methods")
def detection_methods(db: Session = Depends(get_db)):
    return dashboard.detection_method_breakdown(db)


@router.get("/risk-distribution")
def risk_distribution(db: Session = Depends(get_db)):
    return dashboard.risk_distribution(db)
