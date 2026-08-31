"""Insider Threat API — user threat scoring endpoints."""
from fastapi import APIRouter, Depends
from backend.security import require_auth

router = APIRouter(prefix="/api/insider-threat", tags=["insider-threat"], dependencies=[Depends(require_auth)])


@router.get("/scores")
async def get_scores():
    """Return insider threat scores for all monitored users."""
    return {"items": []}
