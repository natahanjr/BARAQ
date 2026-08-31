from fastapi import APIRouter, Depends
from backend.security import require_auth

router = APIRouter(prefix="/api/ueba", tags=["ueba"], dependencies=[Depends(require_auth)])


@router.get("/baselines")
async def get_baselines():
    return {"items": []}


@router.get("/anomalies")
async def get_anomalies():
    return {"items": []}
