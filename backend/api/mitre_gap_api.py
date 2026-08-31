from fastapi import APIRouter, Depends
from backend.security import require_auth
from backend.mitre.gap_analysis import generate_gap_report

router = APIRouter(prefix="/api/mitre", tags=["mitre-gap"], dependencies=[Depends(require_auth)])


@router.get("/gap-report")
async def gap_report():
    return generate_gap_report().model_dump()
