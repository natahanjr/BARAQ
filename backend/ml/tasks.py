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


def _demote_thread_priority() -> None:
    """Run the training thread below normal priority (best effort).

    Retrains contend with the scheduler loop for CPU; at normal priority the
    training burst starves collection/detection (cycles ballooned 20s ->
    100s+). On Windows this pins the thread to below-normal so latency-
    critical stages preempt it; elsewhere it is a no-op.
    """
    try:
        import ctypes

        THREAD_PRIORITY_BELOW_NORMAL = -1
        if hasattr(ctypes.windll, "kernel32"):
            if ctypes.windll.kernel32.SetThreadPriority(
                ctypes.windll.kernel32.GetCurrentThread(),
                THREAD_PRIORITY_BELOW_NORMAL,
            ):
                logger.debug("Training thread priority set below normal")
    except Exception:  # pragma: no cover - non-Windows or restricted env
        pass


def train_in_background(hours=None, validate=True, force=False, kind="manual"):
    """Queue a full retrain on a daemon thread; returns False if one runs.

    ``kind`` labels the run in the model version history (manual / drift /
    incremental). The scheduler uses this so a drift-triggered retrain no
    longer blocks the collection/detection loop for minutes - a synchronous
    retrain observed earlier stalled the loop ~14 minutes.
    """
    if not _train_lock.acquire(blocking=False):
        return False

    def _work():
        _demote_thread_priority()
        db = SessionLocal()
        try:
            result = _bulk_train(db, hours=hours, kind=kind)
            logger.info(
                "Background ML training finished (%s): %s",
                kind,
                result.get("status"),
            )
        except Exception:
            logger.exception("Background ML training failed")
        finally:
            db.close()
            _train_lock.release()

    threading.Thread(target=_work, daemon=True, name="baraq-ml-train").start()
    return True


def training_active():
    return _train_lock.locked()
