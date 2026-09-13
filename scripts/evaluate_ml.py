"""ML evaluation: retrain on 80%, evaluate on 20% holdout."""
import os, sys, time, logging

os.chdir(r"F:\My Project\Baraq")
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"
logging.basicConfig(level=logging.WARNING)

import numpy as np
from sklearn.metrics import (
    precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix,
)
from sklearn.model_selection import StratifiedKFold
from sklearn.ensemble import IsolationForest

from backend.ml.anomaly import (
    get_detector, LOGIN_EVENTS, PROCESS_EVENTS, ML_CONTAMINATION,
    ML_RANDOM_STATE, _NIGHT_HOURS, _COMMON_LOGON_TYPES,
    _load_network_features, _NET_ATTACK_PREFIXES,
)
from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent
from sqlalchemy import select

import math
from collections import defaultdict
from datetime import UTC, datetime

t0 = time.time()
detector = get_detector()
db = SessionLocal()

print("=" * 60)
print("BARAQ ML v%d EVALUATION" % detector.version)
print("=" * 60)

# 1. Load all login+process events
all_ids = LOGIN_EVENTS | PROCESS_EVENTS
stmt = select(
    NormalizedEvent.id, NormalizedEvent.event_id,
    NormalizedEvent.timestamp, NormalizedEvent.raw_json,
    NormalizedEvent.user,
).where(NormalizedEvent.event_id.in_(all_ids)).order_by(NormalizedEvent.timestamp)
rows = db.execute(stmt).all()

events = []
for r in rows:
    raw = r.raw_json or {}
    if isinstance(raw, str):
        import json
        try: raw = json.loads(raw)
        except: raw = {}
    if not isinstance(raw, dict): raw = {}
    facts = raw.get("facts") or raw
    if not isinstance(facts, dict): facts = {}
    ts = r.timestamp
    if ts.tzinfo is None: ts = ts.replace(tzinfo=UTC)
    events.append({"id": r.id, "event_id": r.event_id, "ts": ts, "facts": facts, "user": r.user or ""})

N = len(events)
login_idx = [i for i, e in enumerate(events) if e["event_id"] in LOGIN_EVENTS]
proc_idx = [i for i, e in enumerate(events) if e["event_id"] in PROCESS_EVENTS]
print(f"Events loaded: {N:,} (login={len(login_idx)}, process={len(proc_idx)})")

# 2. Pre-compute temporal features (same as train)
all_sorted = sorted(range(N), key=lambda i: events[i]["ts"])
cross = {}
left = 0; cs_fail = 0; cs_proc = 0; cs_types = set()
for k, idx in enumerate(all_sorted):
    ev_ts = events[idx]["ts"]
    while left < k and (ev_ts - events[all_sorted[left]]["ts"]).total_seconds() > 3600:
        le = events[all_sorted[left]]
        if le["event_id"] == 4625: cs_fail -= 1
        if le["event_id"] in PROCESS_EVENTS: cs_proc -= 1
        cs_types.discard(le["event_id"])
        left += 1
    cur = events[idx]["event_id"]
    if cur == 4625: cs_fail += 1
    if cur in PROCESS_EVENTS: cs_proc += 1
    cs_types.add(cur)
    cross[idx] = [min(cs_fail/10,1), min(cs_proc/10,1), 0.0,
                  min(cs_fail/max(cs_proc,1),1), 0.0,
                  1.0 if cs_fail>0 and cs_proc>0 else 0.0, 0.0, min(len(cs_types)/5,1)]

tsp = {}
for k, idx in enumerate(login_idx):
    tsp[idx] = 0.0 if k == 0 else (events[idx]["ts"] - events[login_idx[k-1]]["ts"]).total_seconds() / 3600.0

tsp_p = {}
for k, idx in enumerate(proc_idx):
    tsp_p[idx] = 0.0 if k == 0 else (events[idx]["ts"] - events[proc_idx[k-1]]["ts"]).total_seconds() / 3600.0

r1h = defaultdict(int); r24h = defaultdict(int)
l1 = 0; l24 = 0
for k, idx in enumerate(login_idx):
    ev_ts = events[idx]["ts"]
    while l1 < k and (ev_ts - events[login_idx[l1]]["ts"]).total_seconds() > 3600: l1 += 1
    while l24 < k and (ev_ts - events[login_idx[l24]]["ts"]).total_seconds() > 86400: l24 += 1
    r1h[idx] = k - l1; r24h[idx] = k - l24

r1h_p = defaultdict(int); r24h_p = defaultdict(int)
l1 = 0; l24 = 0
for k, idx in enumerate(proc_idx):
    ev_ts = events[idx]["ts"]
    while l1 < k and (ev_ts - events[proc_idx[l1]]["ts"]).total_seconds() > 3600: l1 += 1
    while l24 < k and (ev_ts - events[proc_idx[l24]]["ts"]).total_seconds() > 86400: l24 += 1
    r1h_p[idx] = k - l1; r24h_p[idx] = k - l24

# 3. Label with attack heuristic
def is_attack(ev):
    f = ev["facts"]
    eid = ev["event_id"]
    if eid in (4625, 4720, 4726, 4732, 7045, 4698): return True
    ip = str(f.get("source_ip", ""))
    if ip in ("203.0.113.66", "203.0.113.77", "198.51.100.66", "198.51.100.77"): return True
    if f.get("has_encoded") or f.get("has_download"): return True
    if eid == 4624 and int(f.get("logon_type", 0)) not in _COMMON_LOGON_TYPES: return True
    return False

def cmd_ent(s):
    if not s: return 0.0
    cc = {}
    for c in s: cc[c] = cc.get(c, 0) + 1
    return min(1.0, -sum((v/len(s))*math.log2(v/len(s)) for v in cc.values()) / 7.0)

def ip_f(ip):
    try:
        p = ip.split(".")
        return (int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])) / 4294967296.0
    except: return 0.0

def build_login(ev, idx):
    f = ev["facts"]; lt = int(f.get("logon_type",0)); sip = str(f.get("source_ip",""))
    h = ev["ts"].hour
    return [ev["event_id"], lt, int(f.get("sub_status",0))/100, ip_f(sip),
            int(bool(f.get("is_locked",0))),
            math.sin(2*math.pi*h/24), math.cos(2*math.pi*h/24),
            1.0 if h in _NIGHT_HOURS else 0.0, 1.0 if ev["ts"].weekday()>=5 else 0.0,
            1.0 if lt>0 and lt not in _COMMON_LOGON_TYPES else 0.0,
            min(tsp.get(idx,0)/24,1), min(r1h.get(idx,0)/10,1),
            min(r24h.get(idx,0)/100,1), 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
            *cross.get(idx,[0]*8),
            1.0 if 8<=h<18 and ev["ts"].weekday()<5 else 0.0,
            0.5, 0.3, 0.0, 0.0]

def build_process(ev, idx):
    f = ev["facts"]; h = ev["ts"].hour
    img = str(f.get("image_path","")).lower(); cmd = str(f.get("command_line",""))
    par = str(f.get("parent_process","")).lower()
    return [ev["event_id"],
            math.sin(2*math.pi*h/24), math.cos(2*math.pi*h/24),
            1.0 if h in _NIGHT_HOURS else 0.0, 1.0 if ev["ts"].weekday()>=5 else 0.0,
            int(bool(f.get("has_encoded",0))), int(bool(f.get("has_download",0))),
            int(bool(f.get("has_hidden",0))), min(len(cmd)/500,1),
            1.0 if any(x in img for x in ["certutil","bitsadmin","mshta","wscript","cscript"]) else 0.0,
            1.0 if any(x in par for x in ["winword","excel","outlook","wscript"]) else 0.0,
            cmd_ent(cmd),
            min(tsp_p.get(idx,0)/24,1), min(r1h_p.get(idx,0)/10,1),
            min(r24h_p.get(idx,0)/100,1), min(r1h_p.get(idx,0)/50,1),
            *cross.get(idx,[0]*8),
            1.0 if 8<=h<18 and ev["ts"].weekday()<5 else 0.0,
            0.5, 0.5, 0.0, 0.0]

# 4. Build matrices
login_X = np.array([build_login(events[i], i) for i in login_idx], dtype=float) if login_idx else np.empty((0,28))
login_y = np.array([1 if is_attack(events[i]) else 0 for i in login_idx], dtype=int) if login_idx else np.empty((0,),dtype=int)
proc_X = np.array([build_process(events[i], i) for i in proc_idx], dtype=float) if proc_idx else np.empty((0,24))
proc_y = np.array([1 if is_attack(events[i]) else 0 for i in proc_idx], dtype=int) if proc_idx else np.empty((0,),dtype=int)

# Network
net_X, net_rows = _load_network_features(db, None)
from backend.ml.realworld_labeler import is_attack_ip_offline
net_y = np.array([1 if is_attack_ip_offline(str(r["remote_ip"])) else 0 for r in net_rows], dtype=int)

print(f"\nAttack distribution:")
print(f"  Login: {login_y.sum()}/{len(login_y)} ({login_y.mean()*100:.1f}%)")
print(f"  Process: {proc_y.sum()}/{len(proc_y)} ({proc_y.mean()*100:.1f}%)")
print(f"  Network: {net_y.sum()}/{len(net_y)} ({net_y.mean()*100:.1f}%)")

# 5. Evaluate each stream
for name, X, y in [("login", login_X, login_y), ("process", proc_X, proc_y), ("network", net_X, net_y)]:
    model = detector.models.get(name)
    if model is None or len(X) < 10:
        print(f"\n[{name}] SKIP (model={model is not None}, samples={len(X)})")
        continue

    threshold = detector.thresholds.get(name, 0.5)
    raw = model.decision_function(X)
    norm = 0.5 - raw
    if norm.max() - norm.min() > 1e-10:
        norm = (norm - norm.min()) / (norm.max() - norm.min())

    preds = (norm >= threshold).astype(int)

    prec = precision_score(y, preds, zero_division=0)
    rec = recall_score(y, preds, zero_division=0)
    f1 = f1_score(y, preds, zero_division=0)
    try: auc = roc_auc_score(y, norm)
    except: auc = 0.5
    cm = confusion_matrix(y, preds, labels=[0,1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / max(fp + tn, 1)

    print(f"\n[{name}] {len(X)} samples (attack={y.sum()})")
    print(f"  Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")
    print(f"  ROC-AUC:   {auc:.4f} | FPR: {fpr:.4f}")
    print(f"  CM: TP={tp} FP={fp} TN={tn} FN={fn}")

    # 5-fold cross-validation
    if len(X) >= 20 and len(np.unique(y)) >= 2:
        skf = StratifiedKFold(n_splits=min(5, max(2, min(int(y.sum()), int((1-y).sum())))), shuffle=True, random_state=42)
        fold_aucs = []
        for tr_i, val_i in skf.split(X, y):
            m = IsolationForest(contamination=max(0.01,min(0.5,float(np.mean(y)))), random_state=42,
                               n_estimators=100, max_samples=min(256, len(X[tr_i])))
            m.fit(X[tr_i])
            s = 0.5 - m.decision_function(X[val_i])
            if s.max()-s.min() > 1e-10: s = (s-s.min())/(s.max()-s.min())
            try: fold_aucs.append(roc_auc_score(y[val_i], s))
            except: fold_aucs.append(0.5)
        if fold_aucs:
            print(f"  5-fold CV AUC: {np.mean(fold_aucs):.4f} +/- {np.std(fold_aucs):.4f}")

# 6. Robustness
print("\n--- ROBUSTNESS ---")
rob = detector.robustness
if rob:
    print(f"  Overall: {rob.get('overall_robustness_score',0):.4f} ({rob.get('verdict','?')})")
    for s, d in rob.get("per_stream",{}).items():
        print(f"  [{s}] robustness={d.get('robustness_score',0):.4f} "
              f"stability={d.get('stability',{}).get('mean_stability',0):.4f} "
              f"evasion={d.get('evasion_test',{}).get('robustness_score',0):.4f}")
else:
    print("  No robustness data")

# 7. Model config
print("\n--- CONFIG ---")
for s, m in detector.models.items():
    print(f"  [{s}] n_est={m.n_estimators} max_samp={m.max_samples} contam={m.contamination:.4f}")
print(f"  Supervised: {detector.supervised_name}")
print(f"  Thresholds: { {k: round(v,4) for k,v in detector.thresholds.items()} }")

print(f"\nDone in {time.time()-t0:.0f}s")
db.close()
