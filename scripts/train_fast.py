"""Fast batch training: pass shared session to event_feature_vector."""
import sys
import time
import traceback
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from backend.ml.anomaly import (
    event_feature_vector, LOGIN_EVENTS, PROCESS_EVENTS,
    _load_network_features, _NET_ATTACK_PREFIXES,
    get_detector, IsolationForest, ML_CONTAMINATION, ML_RANDOM_STATE,
    _DEFAULT_THRESHOLDS,
)
from backend.ml.realworld_labeler import is_attack_ip_offline, get_attack_ips
from sqlalchemy import select
from datetime import UTC, datetime

def load_login_features(session):
    stmt = select(NormalizedEvent).where(NormalizedEvent.event_id.in_(LOGIN_EVENTS))
    rows = session.scalars(stmt).all()
    X, y = [], []
    for i, ev in enumerate(rows):
        if i % 5000 == 0:
            print(f"    login {i}/{len(rows)}...", flush=True)
        try:
            vec = event_feature_vector(ev, _shared_session=session)
            if vec:
                X.append(vec)
                facts = (ev.raw_json or {}).get("facts", {})
                sip = str(facts.get("source_ip", ""))
                is_attack = (
                    ev.event_id in (4625, 4720, 4726, 4732, 7045, 4698)
                    or is_attack_ip_offline(sip)
                    or bool(facts.get("has_encoded"))
                    or bool(facts.get("has_download"))
                )
                y.append(1 if is_attack else 0)
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass
            continue
    return np.array(X, dtype=float), np.array(y, dtype=int)

def load_process_features(session):
    stmt = select(NormalizedEvent).where(NormalizedEvent.event_id.in_(PROCESS_EVENTS))
    rows = session.scalars(stmt).all()
    X, y = [], []
    for i, ev in enumerate(rows):
        if i % 5000 == 0:
            print(f"    process {i}/{len(rows)}...", flush=True)
        try:
            vec = event_feature_vector(ev, _shared_session=session)
            if vec:
                X.append(vec)
                facts = (ev.raw_json or {}).get("facts", {})
                sip = str(facts.get("source_ip", ""))
                is_attack = (
                    ev.event_id in (4720, 4726, 4732, 7045, 4698)
                    or is_attack_ip_offline(sip)
                    or bool(facts.get("has_encoded"))
                    or bool(facts.get("has_download"))
                    or bool(facts.get("has_hidden"))
                    or any(kw in str(facts.get("command_line", "")).lower() for kw in ["mimikatz", "invoke-expression", "bypass", "downloadstring", "encoded"])
                    or any(kw in str(facts.get("image_path", "")).lower() for kw in ["temp\\", "public\\", "appdata\\"])
                )
                y.append(1 if is_attack else 0)
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass
            continue
    return np.array(X, dtype=float), np.array(y, dtype=int)

print("=== Fast Batch ML Training ===", flush=True)
t0 = time.time()

session = SessionLocal()
try:
    print(f"[{time.time()-t0:.0f}s] Loading login features...", flush=True)
    login_X, login_y = load_login_features(session)
    print(f"[{time.time()-t0:.0f}s] Login: {login_X.shape} pos={int(login_y.sum())} neg={int(len(login_y)-login_y.sum())}", flush=True)

    print(f"[{time.time()-t0:.0f}s] Loading process features...", flush=True)
    process_X, process_y = load_process_features(session)
    print(f"[{time.time()-t0:.0f}s] Process: {process_X.shape} pos={int(process_y.sum())} neg={int(len(process_y)-process_y.sum())}", flush=True)
finally:
    session.close()

print(f"[{time.time()-t0:.0f}s] Loading network features...", flush=True)
network_X, network_rows = _load_network_features(None, None, cutoff=None)
network_y = np.array([
    1 if str(r.get("remote_ip", "")).startswith(_NET_ATTACK_PREFIXES) else 0
    for r in network_rows
], dtype=int) if network_rows else np.empty((0,), dtype=int)
print(f"[{time.time()-t0:.0f}s] Network: {network_X.shape} pos={int(network_y.sum())}", flush=True)

print(f"\n=== Training Models ===", flush=True)
new_models = {}
new_thresholds = dict(_DEFAULT_THRESHOLDS)
stream_X = {}
stream_y = {}
for behavior, X, y in [("login", login_X, login_y), ("process", process_X, process_y), ("network", network_X, network_y)]:
    if len(X) < 3:
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
detector.events_at_train = 253899
detector.version += 1

print(f"[{time.time()-t0:.0f}s] SAVING bundle...", flush=True)
detector._save_meta()
detector._save_bundle()
print(f"[{time.time()-t0:.0f}s] DONE! models={list(new_models.keys())} samples={detector.n_samples} version={detector.version}", flush=True)
