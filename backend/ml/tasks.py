"""Background ML training - run model training off the request thread.

Training blocks the API for seconds; scheduling it in a daemon thread keeps
``POST /api/system/ml/train`` responsive. A non-blocking lock guarantees a
single training run at a time; ``training_active()`` feeds ``/ml/status``.
"""
from __future__ import annotations

import logging
import threading

from backend.database.connection import SessionLocal
from backend.ml.anomaly import get_detector

logger = logging.getLogger("baraq.ml.tasks")

_train_lock = threading.Lock()


def train_in_background(hours: int | None = None, validate: bool = True, force: bool = False) -> bool:
    """Start a background training job; False if one is already running.

    ``hours=None`` trains on the FULL collected history (no sample window).
    """
    if not _train_lock.acquire(blocking=False):
        return False

    def _work() -> None:
        db = SessionLocal()
        try:
            result = get_detector().train(
                db, hours=hours, validate=validate and not force
            )
            logger.info("Background ML training finished: %s", result.get("status"))
        except Exception:  # noqa: BLE001
            logger.exception("Background ML training failed")
        finally:
            db.close()
            _train_lock.release()

    threading.Thread(target=_work, daemon=True, name="baraq-ml-train").start()
    return True


def training_active() -> bool:
    """True while a background training job is running."""
    return _train_lock.locked()
