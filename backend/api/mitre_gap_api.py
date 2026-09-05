"""MITRE ATT&CK Gap Report API — detection coverage analysis."""
import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.security import require_auth

router = APIRouter(prefix="/api/mitre", tags=["mitre-gap"], dependencies=[Depends(require_auth)])

logger = logging.getLogger("baraq.mitre.gap_api")


@router.get("/gap-report")
async def gap_report(db: Session = Depends(get_db)):
    """Generate a detection coverage gap analysis across ATT&CK techniques."""
    from backend.mitre.gap_analysis import generate_gap_report

    try:
        rules_engine = None
        try:
            from backend.detection.rules_engine import RulesEngine
            rules_engine = RulesEngine(db)
        except Exception as e:
            logger.warning("Could not load rules engine for gap report: %s", e)

        report = generate_gap_report(rules_engine=rules_engine)
        return report.model_dump()
    except Exception as e:
        raise HTTPException(500, f"Failed to generate gap report: {type(e).__name__}")
