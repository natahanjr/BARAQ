"""MITRE ATT&CK Gap Report API — detection coverage analysis."""
from fastapi import APIRouter, Depends, HTTPException
from backend.security import require_auth
from backend.mitre.gap_analysis import generate_gap_report

router = APIRouter(prefix="/api/mitre", tags=["mitre-gap"], dependencies=[Depends(require_auth)])


@router.get("/gap-report")
async def gap_report():
    """Generate a detection coverage gap analysis across ATT&CK techniques."""
    try:
        return generate_gap_report().model_dump()
    except Exception as e:
        raise HTTPException(500, f"Failed to generate gap report: {type(e).__name__}")
