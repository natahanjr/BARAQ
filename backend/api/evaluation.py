"""Evaluation framework API endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import EvaluationRun
from backend.evaluation.evaluator import run_evaluation

logger = logging.getLogger("sentinel.api.evaluation")
router = APIRouter(prefix="/api/evaluation", tags=["evaluation"])


@router.post("/run")
def run(with_ml: bool = True, db: Session = Depends(get_db)):
    return run_evaluation(db, with_ml=with_ml)


@router.get("/results")
def results(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(EvaluationRun).order_by(EvaluationRun.created_at.desc()).limit(limit)
    ).all()
    return {"items": [r.to_dict() for r in rows]}


@router.get("/latest")
def latest(db: Session = Depends(get_db)):
    overall = db.scalars(
        select(EvaluationRun)
        .where(EvaluationRun.scenario == "overall")
        .order_by(EvaluationRun.created_at.desc())
        .limit(1)
    ).first()
    if not overall:
        return {"items": []}
    runs = db.scalars(
        select(EvaluationRun)
        .where(
            EvaluationRun.scenario != "overall",
            EvaluationRun.created_at == overall.created_at,
        )
        .order_by(EvaluationRun.id)
    ).all()
    return {"items": [r.to_dict() for r in runs], "overall": overall.to_dict()}
