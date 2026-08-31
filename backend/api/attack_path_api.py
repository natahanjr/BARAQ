from fastapi import APIRouter, Depends
from pydantic import BaseModel
from backend.security import require_auth
from backend.ml.attack_path import AttackPathPredictor
from backend.risk.blast_radius import BlastRadiusAnalyzer

router = APIRouter(prefix="/api/attack-path", tags=["attack-path"], dependencies=[Depends(require_auth)])

_predictor = AttackPathPredictor()
_analyzer = BlastRadiusAnalyzer()


class PredictBody(BaseModel):
    entry_tactic: str
    compromised_tactics: list[str] = []


class BlastRadiusBody(BaseModel):
    entity: str
    entity_type: str = "host"
    connections: list[dict] = []


@router.post("/predict")
async def predict(body: PredictBody):
    tactics = list(set([body.entry_tactic] + body.compromised_tactics))
    path = _predictor.build_attack_path(body.entry_tactic, tactics)
    return path.model_dump()


@router.post("/blast-radius")
async def blast_radius(body: BlastRadiusBody):
    result = _analyzer.calculate(body.entity, body.entity_type, body.connections)
    return result.model_dump()
