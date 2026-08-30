"""Debug ML training step by step with timing."""
import logging
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("step_debug")

from backend.database.connection import SessionLocal
from backend.ml.anomaly import (
    get_detector, _load_behavior_features, _load_network_features,
    LOGIN_EVENTS, PROCESS_EVENTS, MLAnomalyDetector, _behavior_of,
    event_feature_vector, orm_event_is_corrupted, _verdict_map,
)
from backend.ml.anomaly import HAS_XGBOOST, HAS_ENSEMBLE
from sqlalchemy import select
from backend.database.models import NormalizedEvent
from datetime import UTC, datetime
import numpy as np

db = SessionLocal()
detector = get_detector()

log.info("Step 1: _load_behavior_features (login)...")
t0 = time.time()
login_X, login_y = _load_behavior_features(db, None, LOGIN_EVENTS, with_labels=True, cutoff=None)
log.info("  -> %.1fs, X=%s", time.time()-t0, login_X.shape)

log.info("Step 2: _load_behavior_features (process)...")
t0 = time.time()
process_X, process_y = _load_behavior_features(db, None, PROCESS_EVENTS, with_labels=True, cutoff=None)
log.info("  -> %.1fs, X=%s", time.time()-t0, process_X.shape)

log.info("Step 3: _load_network_features...")
t0 = time.time()
network_X, network_rows = _load_network_features(db, None, cutoff=None)
log.info("  -> %.1fs, X=%s", time.time()-t0, network_X.shape)

log.info("Step 4: IsolationForest fitting...")
from sklearn.ensemble import IsolationForest
from backend.config import ML_CONTAMINATION, ML_RANDOM_STATE
for name, X in [("login", login_X), ("process", process_X), ("network", network_X)]:
    t0 = time.time()
    if len(X) < 3:
        log.info("  %s: SKIP (len=%d)", name, len(X))
        continue
    m = IsolationForest(contamination=ML_CONTAMINATION, random_state=ML_RANDOM_STATE, n_estimators=100, max_samples=min(256, len(X)))
    m.fit(X)
    log.info("  %s: %.1fs, fitted %d samples", name, time.time()-t0, len(X))

log.info("Step 5: _labeled_samples (THE BOTTLENECK?)...")
t0 = time.time()
try:
    labeled = detector._labeled_samples(db)
    for beh, (atk, ben) in labeled.items():
        log.info("  %s: attack=%d benign=%d", beh, len(atk), len(ben))
    log.info("  -> %.1fs", time.time()-t0)
except Exception as e:
    log.error("  FAILED at %.1fs: %s", time.time()-t0, e)
    traceback.print_exc()

db.close()
log.info("Done.")
