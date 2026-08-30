"""Debug ML training - find where it hangs."""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("debug_train")

from backend.database.connection import SessionLocal

db = SessionLocal()

# Step 1: Feature loading
log.info("Step 1: Loading login features...")
t0 = time.time()
from backend.ml.anomaly import _load_behavior_features, LOGIN_EVENTS, PROCESS_EVENTS
from datetime import datetime, UTC
since = None  # full history

login_X, login_y = _load_behavior_features(db, since, LOGIN_EVENTS, with_labels=True, cutoff=None)
log.info("Login features loaded in %.1fs: X=%s y=%s", time.time()-t0, login_X.shape, login_y.shape)

log.info("Step 2: Loading process features...")
t0 = time.time()
process_X, process_y = _load_behavior_features(db, since, PROCESS_EVENTS, with_labels=True, cutoff=None)
log.info("Process features loaded in %.1fs: X=%s y=%s", time.time()-t0, process_X.shape, process_y.shape)

log.info("Step 3: Loading network features...")
t0 = time.time()
from backend.ml.anomaly import _load_network_features
network_X, network_rows = _load_network_features(db, since, cutoff=None)
log.info("Network features loaded in %.1fs: X=%s rows=%d", time.time()-t0, network_X.shape, len(network_rows))

db.close()
log.info("All feature loading complete. Total samples: %d", len(login_X)+len(process_X)+len(network_X))
