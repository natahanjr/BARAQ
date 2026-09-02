"""Train ML on capped event set (5K per stream) to stay under timeout."""
import sys, time
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
from backend.ml.realworld_labeler import is_attack_ip_offline
from sqlalchemy import select
from datetime import UTC, datetime

MAX_EVENTS = 5000

def load_features(session, event_ids, label, limit=MAX_EVENTS):
    stmt = select(NormalizedEvent).where(NormalizedEvent.event_id.in_(event_ids)).limit(limit)
    rows = session.scalars(stmt).all()
    X, y = [], []
    for i, ev in enumerate(rows):
        if i % 1000 == 0:
            print(f"    {label} {i}/{len(rows)}...", flush=True)
        try:
            vec = event_feature_vector(ev, _shared_session=session)
            if vec:
                X.append(vec)
                facts = (ev.raw_json or {}).get("facts", {})
                sip = str(facts.get("source_ip", ""))
                is_atk = (
                    ev.event_id in (4625, 4720, 4726, 4732, 7045, 4698)
                    or is_attack_ip_offline(sip)
                    or bool(facts.get("has_encoded")) or bool(facts.get("has_download"))
                )
                y.append(1 if is_atk else 0)
        except Exception:
            try: session.rollback()
            except: pass
    return np.array(X, dtype=float), np.array(y, dtype=int)

print("=== Capped ML Training (5K per stream) ===", flush=True)
t0 = time.time()

print(f"[{time.time()-t0:.0f}s] Login...", flush=True)
s1 = SessionLocal()
try:
    login_X, login_y = load_features(s1, LOGIN_EVENTS, "login")
finally:
    s1.close()
print(f"[{time.time()-t0:.0f}s] Login: {login_X.shape} pos={int(login_y.sum())}", flush=True)

print(f"[{time.time()-t0:.0f}s] Process...", flush=True)
s2 = SessionLocal()
try:
    process_X, process_y = load_features(s2, PROCESS_EVENTS, "process")
finally:
    s2.close()
print(f"[{time.time()-t0:.0f}s] Process: {process_X.shape} pos={int(process_y.sum())}", flush=True)

print(f"[{time.time()-t0:.0f}s] Network...", flush=True)
network_X, network_rows = _load_network_features(None, None, cutoff=None)
network_y = np.array([1 if is_attack_ip_offline(r.get("remote_ip","")) else 0 for r in network_rows], dtype=int) if network_rows else np.empty((0,),dtype=int)
print(f"[{time.time()-t0:.0f}s] Network: {network_X.shape}", flush=True)

new_models = {}
new_thresholds = dict(_DEFAULT_THRESHOLDS)
stream_X, stream_y = {}, {}
for beh, X, y in [("login",login_X,login_y),("process",process_X,process_y),("network",network_X,network_y)]:
    if len(X) < 3: continue
    m = IsolationForest(contamination=ML_CONTAMINATION, random_state=ML_RANDOM_STATE, n_estimators=100, max_samples=min(256,len(X)))
    m.fit(X)
    new_models[beh] = m
    stream_X[beh], stream_y[beh] = X, y
    print(f"[{time.time()-t0:.0f}s] {beh}: IF fitted ({len(X)})", flush=True)

detector = get_detector()
new_sup = {}
for beh in ("login","process","network"):
    X, y = stream_X.get(beh), stream_y.get(beh)
    if X is None or len(X) < 4: continue
    atk, ben = X[y.astype(bool)], X[~y.astype(bool)]
    if len(atk) < 3 or len(ben) < 3: continue
    X_all = np.vstack([ben, atk])
    y_all = np.array([0]*len(ben)+[1]*len(atk))
    model, name = detector._build_classifier(X_all, y_all)
    new_sup[beh] = model
    print(f"[{time.time()-t0:.0f}s] {beh}: {name}", flush=True)

for beh in new_models:
    t, b = detector._tune_threshold(new_models[beh], stream_X[beh], stream_y.get(beh), supervised=new_sup.get(beh))
    new_thresholds[beh] = t
    print(f"[{time.time()-t0:.0f}s] {beh}: threshold={t:.4f}", flush=True)

detector.models = new_models
detector.thresholds = new_thresholds
detector.supervised_by_stream = new_sup
detector.supervised_name = "+".join(new_sup.keys()) or "none"
detector.n_samples = int(len(login_X)+len(process_X)+len(network_X))
detector.trained_at = datetime.now(UTC).isoformat()
detector.events_at_train = int(len(login_X) + len(process_X) + len(network_X))
detector.version += 1
detector._save_meta()
detector._save_bundle()
print(f"\n[DONE in {time.time()-t0:.0f}s] models={list(new_models.keys())} samples={detector.n_samples} version={detector.version}", flush=True)
