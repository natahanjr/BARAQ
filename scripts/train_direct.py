"""Train ML model directly (bypass API)."""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("train_direct")

from backend.database.connection import SessionLocal
from backend.ml.anomaly import get_detector

log.info("Starting ML training (full history, forced)...")
db = SessionLocal()
try:
    result = get_detector().train(db, hours=None, validate=False)
    log.info("Training result: %s", result)
except Exception:
    log.exception("Training failed")
finally:
    db.close()

log.info("Done.")
