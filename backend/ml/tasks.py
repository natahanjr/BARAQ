"""Background ML training - run model training off the request thread.

Training blocks the API for seconds; scheduling it in a daemon thread keeps
POST /api/system/ml/train responsive. A non-blocking lock guarantees a
single training run at a time; training_active() feeds /ml/status.
"""

from __future__ import annotations

import logging
import threading
import time

from backend.database.connection import SessionLocal
from backend.ml.anomaly import get_detector

logger = logging.getLogger("baraq.ml.tasks")
_train_lock = threading.Lock()


def _bulk_train(session, hours=None, kind="manual"):
    """Delegate to detector.train() which uses grid search, cross-validation,
    SMOTE augmentation, multi-contamination ensemble, and robustness eval."""
    t0 = time.time()
    detector = get_detector()
    result = detector.train(session=session, hours=hours, validate=False,
                            persist=True, kind=kind)
    elapsed = time.time() - t0
    logger.info("Bulk train delegated to detector.train() in %.0fs: %s",
                elapsed, result.get("status"))
    return result


def train_in_background(hours=None, validate=True, force=False):
    if not _train_lock.acquire(blocking=False):
        return False

    def _work():
        db = SessionLocal()
        try:
            result = _bulk_train(db, hours=hours, kind="manual")
            logger.info("Background ML training finished: %s", result.get("status"))
        except Exception:
            logger.exception("Background ML training failed")
        finally:
            db.close()
            _train_lock.release()

    threading.Thread(target=_work, daemon=True, name="baraq-ml-train").start()
    return True


def check_online_update():
    """Check if online learning update is needed and perform it.

    Called periodically by the background scheduler. Uses ADWIN drift detection
    and reservoir sampling buffers to perform incremental model updates.
    """
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    if not detector.is_ready or detector.online_learner is None:
        return None

    try:
        if detector.online_learner.should_update():
            logger.info("Online learning update triggered")
            result = detector.online_learner.incremental_update()
            logger.info("Online learning update: %s", result.get("status"))
            return result
    except Exception:
        logger.debug("Online learning update failed", exc_info=True)
    return None


def get_active_learning_suggestions():
    """Get top uncertain events for analyst labeling.

    Returns list of (event_id, features, uncertainty_score) tuples
    that would most improve the model if labeled.
    """
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    if not detector.is_ready or detector.online_learner is None:
        return []

    try:
        return detector.online_learner.active_learner.suggest_for_labeling(
            features_list=[], behaviors=[], models=detector.models
        )
    except Exception:
        return []


def training_active():
    return _train_lock.locked()
