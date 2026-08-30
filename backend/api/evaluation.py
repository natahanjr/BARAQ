"""Evaluation framework API endpoints."""

from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import ML_VALIDATE_ON_REAL
from backend.database.connection import get_db
from backend.database.models import EvaluationRun
from backend.evaluation.evaluator import run_evaluation
from backend.evaluation.holdout import run_holdout_evaluation
from backend.security import require_admin, require_auth

logger = logging.getLogger("baraq.api.evaluation")
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
    use_real_baseline: bool | None = None,
    randomize: bool = False,
    seed: int = 20260806,
    db: Session = Depends(get_db),
):
    """Run the external-validity evaluation (hold-out test set + real baseline).

    ``randomize=True`` applies seeded domain randomization (timing/address
    jitter) to the hold-out attacks to de-risk deterministic fixtures. When
    ``use_real_baseline`` is not supplied it follows ``ML_VALIDATE_ON_REAL``
    (default True): the negative class is live host telemetry rather than the
    synthetic benign baseline.
    """
    use_real = ML_VALIDATE_ON_REAL if use_real_baseline is None else use_real_baseline
    return run_holdout_evaluation(
        db,
        with_ml=with_ml,
        use_real_baseline=use_real,
        randomize=randomize,
        seed=seed,
    )


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
    # Scenario runs of the same suite are committed microseconds apart, so
    # match by a small time window around the overall run instead of exact
    # timestamp equality (which always came back empty).
    window = timedelta(seconds=10)
    runs = db.scalars(
        select(EvaluationRun)
        .where(
            EvaluationRun.scenario != "overall",
            EvaluationRun.created_at >= overall.created_at - window,
            EvaluationRun.created_at <= overall.created_at + window,
        )
        .order_by(EvaluationRun.id)
    ).all()
    return {"items": [r.to_dict() for r in runs], "overall": overall.to_dict()}


@router.post("/full-db", dependencies=[Depends(require_admin)])
def run_full_db(use_ml: bool = True, db: Session = Depends(get_db)):
    """Evaluate detection accuracy against ALL events in the production DB."""
    from backend.evaluation.full_db import run_full_db_evaluation
    return run_full_db_evaluation(db, use_ml=use_ml)
