"""UEBA API — user entity behavior analytics endpoints."""
from fastapi import APIRouter, Depends
from backend.security import require_auth

router = APIRouter(prefix="/api/ueba", tags=["ueba"], dependencies=[Depends(require_auth)])


@router.get("/baselines")
async def get_baselines():
    """Return behavioral baselines for all profiled users."""
    return {"items": []}


@router.get("/anomalies")
async def get_anomalies():
    """Return detected behavioral anomalies."""
    return {"items": []}
