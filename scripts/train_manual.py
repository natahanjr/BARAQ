"""Train ML using the debug approach that works."""
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)

from backend.database.connection import SessionLocal
from backend.ml.anomaly import (
    get_detector, _load_behavior_features, _load_network_features,
    LOGIN_EVENTS, PROCESS_EVENTS, IsolationForest,
    ML_CONTAMINATION, ML_RANDOM_STATE, _NET_ATTACK_PREFIXES,
    _DEFAULT_THRESHOLDS,
)
import numpy as np
from datetime import UTC, datetime

def y_info(y):
    if hasattr(y, 'shape'):
        return f"shape={y.shape} pos={int(y.sum())} neg={int(len(y)-y.sum())}"
    return f"len={len(y)}"

print("=== Step-by-step ML Training ===", flush=True)
t0 = time.time()

print(f"[{time.time()-t0:.0f}s] Loading login features...", flush=True)
login_X, login_y = _load_behavior_features(None, None, LOGIN_EVENTS, with_labels=True, cutoff=None)
print(f"[{time.time()-t0:.0f}s] Login: X={login_X.shape} {y_info(login_y)}", flush=True)

print(f"[{time.time()-t0:.0f}s] Loading process features...", flush=True)
process_X, process_y = _load_behavior_features(None, None, PROCESS_EVENTS, with_labels=True, cutoff=None)
print(f"[{time.time()-t0:.0f}s] Process: X={process_X.shape} {y_info(process_y)}", flush=True)

print(f"[{time.time()-t0:.0f}s] Loading network features...", flush=True)
network_X, network_rows = _load_network_features(None, None, cutoff=None)
print(f"[{time.time()-t0:.0f}s] Network: X={network_X.shape}", flush=True)

network_y = np.array([
    1 if str(r.get("remote_ip", "")).startswith(_NET_ATTACK_PREFIXES) else 0
    for r in network_rows
], dtype=int) if network_rows else np.empty((0,), dtype=int)
print(f"[{time.time()-t0:.0f}s] Network labels: {y_info(network_y)}", flush=True)

new_models = {}
new_thresholds = dict(_DEFAULT_THRESHOLDS)
stream_X = {}
stream_y = {}
for behavior, X, y in [("login", login_X, login_y), ("process", process_X, process_y), ("network", network_X, network_y)]:
    if len(X) < 3:
        print(f"[{time.time()-t0:.0f}s] {behavior}: SKIP", flush=True)
        continue
    m = IsolationForest(contamination=ML_CONTAMINATION, random_state=ML_RANDOM_STATE, n_estimators=100, max_samples=min(256, len(X)))
    m.fit(X)
    new_models[behavior] = m
    stream_X[behavior] = X
    stream_y[behavior] = y
    print(f"[{time.time()-t0:.0f}s] {behavior}: IF fitted ({len(X)} samples)", flush=True)

detector = get_detector()
new_supervised_by_stream = {}
for behavior in ("login", "process", "network"):
    X = stream_X.get(behavior)
    y = stream_y.get(behavior)
    if X is None or y is None or len(X) < 4:
        continue
    atk = X[y.astype(bool)]
    ben = X[~y.astype(bool)]
    min_attacks = 3 if behavior == "network" else 10
    if len(atk) < min_attacks or len(ben) < 3:
        print(f"[{time.time()-t0:.0f}s] {behavior}: skip supervised (atk={len(atk)} ben={len(ben)})", flush=True)
        continue
    X_all = np.vstack([ben, atk])
    y_all = np.array([0]*len(ben) + [1]*len(atk))
    model, name = detector._build_classifier(X_all, y_all)
    new_supervised_by_stream[behavior] = model
    print(f"[{time.time()-t0:.0f}s] {behavior}: {name} trained (atk={len(atk)} ben={len(ben)})", flush=True)

for behavior in new_models:
    t, b = detector._tune_threshold(new_models[behavior], stream_X[behavior], stream_y.get(behavior), supervised=new_supervised_by_stream.get(behavior))
    new_thresholds[behavior] = t
    print(f"[{time.time()-t0:.0f}s] {behavior}: threshold={t:.4f}", flush=True)

detector.models = new_models
detector.thresholds = new_thresholds
detector.supervised_by_stream = new_supervised_by_stream
detector.supervised_name = next(iter(new_supervised_by_stream.values()), None) and "+".join(new_supervised_by_stream.keys()) or "none"
detector.n_samples = int(len(login_X) + len(process_X) + len(network_X))
detector.trained_at = datetime.now(UTC).isoformat()
detector.events_at_train = 133899
detector.version += 1

print(f"[{time.time()-t0:.0f}s] SAVING bundle...", flush=True)
detector._save_meta()
detector._save_bundle()
print(f"[{time.time()-t0:.0f}s] DONE! models={list(new_models.keys())} samples={detector.n_samples} version={detector.version}", flush=True)
