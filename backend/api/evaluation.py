"""Evaluation framework API endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import EvaluationRun
from backend.evaluation.evaluator import run_evaluation
from backend.evaluation.holdout import run_holdout_evaluation
from backend.security import require_admin, require_auth

logger = logging.getLogger("sentinel.api.evaluation")
router = APIRouter(
    prefix="/api/evaluation",
    tags=["evaluation"],
    dependencies=[Depends(require_auth)],
)


@router.post("/run", dependencies=[Depends(require_admin)])
def run(with_ml: bool = True, db: Session = Depends(get_db)):
    return run_evaluation(db, with_ml=with_ml)


@router.post("/holdout", dependencies=[Depends(require_admin)])
def run_holdout(
    with_ml: bool = True,
    use_real_baseline: bool = True,
    db: Session = Depends(get_db),
):
    """Run the external-validity evaluation (hold-out test set + real baseline)."""
    return run_holdout_evaluation(db, with_ml=with_ml, use_real_baseline=use_real_baseline)


@router.get("/results")
def results(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
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
