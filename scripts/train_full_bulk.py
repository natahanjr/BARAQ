"""FULL training: optimized bulk pre-compute with sliding window."""
import math, sys, time
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from pathlib import Path
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, NetworkConnection
from backend.ml.anomaly import (
    get_detector, IsolationForest, ML_CONTAMINATION, ML_RANDOM_STATE,
    _DEFAULT_THRESHOLDS, LOGIN_EVENTS, PROCESS_EVENTS,
    _COMMON_LOGON_TYPES, _NIGHT_HOURS,
)
from backend.ml.realworld_labeler import is_attack_ip_offline
from sqlalchemy import select

def bulk_load_events(session):
    t0 = time.time()
    stmt = select(
        NormalizedEvent.id, NormalizedEvent.event_id, NormalizedEvent.timestamp,
        NormalizedEvent.raw_json, NormalizedEvent.user,
    ).where(NormalizedEvent.event_id.in_(LOGIN_EVENTS | PROCESS_EVENTS)
    ).order_by(NormalizedEvent.timestamp)
    rows = session.execute(stmt).all()
    events = []
    for r in rows:
        facts = (r.raw_json or {}).get("facts") or {}
        ts = r.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        events.append({"id": r.id, "event_id": r.event_id, "ts": ts, "facts": facts, "user": r.user or ""})
    print(f"  Loaded {len(events)} events in {time.time()-t0:.1f}s", flush=True)
    return events

def bulk_load_network(session):
    t0 = time.time()
    rows = session.execute(select(
        NetworkConnection.remote_ip, NetworkConnection.remote_port,
        NetworkConnection.bytes_sent, NetworkConnection.bytes_recv,
        NetworkConnection.duration_seconds, NetworkConnection.observed_at,
    )).all()
    print(f"  Loaded {len(rows)} network rows in {time.time()-t0:.1f}s", flush=True)
    return rows

def precompute_temporals(events):
    """O(N) pre-computation using sliding window."""
    t0 = time.time()
    N = len(events)

    login_idx = [i for i, e in enumerate(events) if e["event_id"] in LOGIN_EVENTS]
    process_idx = [i for i, e in enumerate(events) if e["event_id"] in PROCESS_EVENTS]

    # time_since_prev: time since previous event in same stream
    tsp = {}
    for name, indices in [("login", login_idx), ("process", process_idx)]:
        for k, idx in enumerate(indices):
            tsp[(name, idx)] = 0.0 if k == 0 else (events[idx]["ts"] - events[indices[k-1]]["ts"]).total_seconds() / 3600.0

    # recent counts using sliding window (two-pointer)
    r1h = defaultdict(int)
    r24h = defaultdict(int)
    for name, indices in [("login", login_idx), ("process", process_idx)]:
        if not indices:
            continue
        left_1h = 0
        left_24h = 0
        for k, idx in enumerate(indices):
            ev_ts = events[idx]["ts"]
            while left_1h < k and (ev_ts - events[indices[left_1h]]["ts"]).total_seconds() > 3600:
                left_1h += 1
            while left_24h < k and (ev_ts - events[indices[left_24h]]["ts"]).total_seconds() > 86400:
                left_24h += 1
            r1h[(name, idx)] = k - left_1h
            r24h[(name, idx)] = k - left_24h

    # Failed login velocity per IP
    fail_ip = defaultdict(list)
    for i, e in enumerate(events):
        if e["event_id"] == 4625:
            ip = str(e["facts"].get("source_ip", ""))
            if ip:
                fail_ip[ip].append((e["ts"], i))

    # Logon type counts in 1h window
    lt1h = defaultdict(lambda: defaultdict(int))
    left = 0
    for k, idx in enumerate(login_idx):
        ev_ts = events[idx]["ts"]
        while left < k and (ev_ts - events[login_idx[left]]["ts"]).total_seconds() > 3600:
            left += 1
        for j in range(left, k+1):
            lt = int(events[login_idx[j]]["facts"].get("logon_type", 0))
            lt1h[idx][lt] += 1

    # IP diversity per user (24h sliding window)
    user_logins = defaultdict(list)
    for i, e in enumerate(events):
        if e["event_id"] in (4624, 4625):
            user_logins[e["user"]].append((e["ts"], i, str(e["facts"].get("source_ip", ""))))
    ip_div = {}
    for user, logins in user_logins.items():
        left = 0
        for k, (ts, idx, ip) in enumerate(logins):
            while left < k and (ts - logins[left][0]).total_seconds() > 86400:
                left += 1
            unique = set(logins[j][2] for j in range(left, k+1))
            total = k - left + 1
            ip_div[idx] = len(unique) / max(total, 1)

    # Login z-score (24h)
    lz = {}
    left = 0
    for k, idx in enumerate(login_idx):
        ev_ts = events[idx]["ts"]
        while left < k and (ev_ts - events[login_idx[left]]["ts"]).total_seconds() > 86400:
            left += 1
        if k - left < 2:
            lz[idx] = 0.0
            continue
        gaps = [(events[login_idx[j]]["ts"] - events[login_idx[j-1]]["ts"]).total_seconds() / 60.0
                for j in range(max(left+1, k-49), k+1)]
        if len(gaps) < 2:
            lz[idx] = 0.0
            continue
        mean_g = sum(gaps) / len(gaps)
        std_g = (sum((g-mean_g)**2 for g in gaps) / len(gaps)) ** 0.5
        lz[idx] = 0.0 if std_g == 0 else min(1.0, max(0.0, abs((gaps[-1] - mean_g) / std_g) / 3.0))

    # Cross-stream: counts per 1h window (use all events sorted by time)
    all_sorted = sorted(range(N), key=lambda i: events[i]["ts"])
    cross = {}
    left = 0
    for k, idx in enumerate(all_sorted):
        ev_ts = events[idx]["ts"]
        while left < k and (ev_ts - events[all_sorted[left]]["ts"]).total_seconds() > 3600:
            left += 1
        failed = sum(1 for j in range(left, k+1) if events[all_sorted[j]]["event_id"] == 4625)
        procs = sum(1 for j in range(left, k+1) if events[all_sorted[j]]["event_id"] in PROCESS_EVENTS)
        types = len(set(events[all_sorted[j]]["event_id"] for j in range(left, k+1)))
        t_since = (events[all_sorted[-1]]["ts"] - ev_ts).total_seconds() / 3600.0 if k < len(all_sorted)-1 else 0.0
        cross[idx] = [
            min(failed/10, 1), min(procs/10, 1), 0.0,
            min(failed/max(procs,1), 1), min(t_since, 1),
            1.0 if failed > 0 and procs > 0 else 0.0, 0.0,
            min(types/5, 1),
        ]

    print(f"  Pre-computed in {time.time()-t0:.1f}s", flush=True)
    return {"tsp": tsp, "r1h": r1h, "r24h": r24h, "fail_ip": fail_ip,
            "lt1h": lt1h, "ip_div": ip_div, "lz": lz, "cross": cross,
            "login_idx": login_idx, "process_idx": process_idx}

def ip_float(ip):
    try:
        p = ip.split(".")
        return (int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])) / 4294967296.0
    except:
        return 0.0

def shannon(counter):
    t = sum(counter.values())
    if t == 0: return 0.0
    return -sum((c/t)*math.log2(c/t) for c in counter.values() if c > 0)

def cmd_entropy(s):
    if not s: return 0.0
    cc = {}
    for c in s: cc[c] = cc.get(c,0)+1
    return min(1.0, -sum((v/len(s))*math.log2(v/len(s)) for v in cc.values()) / 7.0)

def is_atk(ev):
    f = ev["facts"]
    eid = ev["event_id"]
    if eid in (4625,4720,4726,4732,7045,4698): return True
    sip = str(f.get("source_ip",""))
    if is_attack_ip_offline(sip): return True
    if f.get("has_encoded") or f.get("has_download"): return True
    if eid == 4624 and int(f.get("logon_type",0)) not in _COMMON_LOGON_TYPES: return True
    return False

def build_login(ev, idx, tc):
    f = ev["facts"]
    lt = int(f.get("logon_type",0))
    sip = str(f.get("source_ip",""))
    sub = int(f.get("sub_status",0))
    locked = int(bool(f.get("is_locked",0)))
    h = ev["ts"].hour
    hs = math.sin(2*math.pi*h/24); hc = math.cos(2*math.pi*h/24)
    night = 1.0 if h in _NIGHT_HOURS else 0.0
    we = 1.0 if ev["ts"].weekday()>=5 else 0.0
    unusual = 1.0 if lt>0 and lt not in _COMMON_LOGON_TYPES else 0.0

    tsp = tc["tsp"].get(("login",idx),0)
    r1h = tc["r1h"].get(("login",idx),0)
    r24h = tc["r24h"].get(("login",idx),0)

    f5=f15=f60=0.0
    if sip in tc["fail_ip"]:
        now = ev["ts"]
        for ts,_ in reversed(tc["fail_ip"][sip]):
            dm = (now-ts).total_seconds()/60
            if dm>60: break
            f60+=1
            if dm<=15: f15+=1
            if dm<=5: f5+=1

    tc1h = tc["lt1h"].get(idx,{})
    ent = shannon(tc1h)
    me = math.log2(max(len(tc1h),1))
    nent = min(1.0, ent/max(me,1)) if me>0 else 0.0
    idiv = tc["ip_div"].get(idx,0)
    z = tc["lz"].get(idx,0)
    cr = tc["cross"].get(idx,[0]*8)
    bh = 1.0 if 8<=h<18 and ev["ts"].weekday()<5 else 0.0

    return [ev["event_id"], lt, sub/100, ip_float(sip), locked,
            hs, hc, night, we, unusual,
            min(tsp/24,1), min(r1h/10,1), min(r24h/100,1), 0.0,
            min(f5/2,1), min(f15/5,1), min(f60/10,1), nent, idiv, z, 0.0,
            *cr, bh, 0.5, 0.3, 0.0, 0.0]

def build_process(ev, idx, tc):
    f = ev["facts"]
    h = ev["ts"].hour
    hs = math.sin(2*math.pi*h/24); hc = math.cos(2*math.pi*h/24)
    night = 1.0 if h in _NIGHT_HOURS else 0.0
    we = 1.0 if ev["ts"].weekday()>=5 else 0.0
    img = str(f.get("image_path","")).lower()
    cmd = str(f.get("command_line",""))
    par = str(f.get("parent_process","")).lower()
    he = int(bool(f.get("has_encoded",0)))
    hd = int(bool(f.get("has_download",0)))
    hh = int(bool(f.get("has_hidden",0)))
    cl = len(cmd)
    lol = 1.0 if any(x in img for x in ["certutil","bitsadmin","mshta","wscript","cscript"]) else 0.0
    rp = 1.0 if any(x in par for x in ["winword","excel","outlook","wscript"]) else 0.0
    ce = cmd_entropy(cmd)
    tsp = tc["tsp"].get(("process",idx),0)
    r1h = tc["r1h"].get(("process",idx),0)
    r24h = tc["r24h"].get(("process",idx),0)
    cr = tc["cross"].get(idx,[0]*8)
    bh = 1.0 if 8<=h<18 and ev["ts"].weekday()<5 else 0.0

    return [ev["event_id"], hs, hc, night, we, he, hd, hh,
            min(cl/500,1), lol, rp, ce,
            min(tsp/24,1), min(r1h/10,1), min(r24h/100,1), min(r1h/50,1),
            *cr, bh, 0.5, 0.5, 0.0, 0.0]

print("=== FULL ML Training ===", flush=True)
t0 = time.time()

session = SessionLocal()
try:
    print(f"[{time.time()-t0:.0f}s] Loading...", flush=True)
    events = bulk_load_events(session)
    net_rows = bulk_load_network(session)
finally:
    session.close()

print(f"[{time.time()-t0:.0f}s] Pre-computing...", flush=True)
tc = precompute_temporals(events)

print(f"[{time.time()-t0:.0f}s] Building login features...", flush=True)
login_X = np.array([build_login(events[i], i, tc) for i in tc["login_idx"]], dtype=float)
login_y = np.array([1 if is_atk(events[i]) else 0 for i in tc["login_idx"]], dtype=int)
print(f"  Login: {login_X.shape} pos={int(login_y.sum())}", flush=True)

print(f"[{time.time()-t0:.0f}s] Building process features...", flush=True)
process_X = np.array([build_process(events[i], i, tc) for i in tc["process_idx"]], dtype=float)
process_y = np.array([1 if is_atk(events[i]) else 0 for i in tc["process_idx"]], dtype=int)
print(f"  Process: {process_X.shape} pos={int(process_y.sum())}", flush=True)

print(f"[{time.time()-t0:.0f}s] Building network features...", flush=True)
from collections import defaultdict as dd
from backend.ml.anomaly import _ip_subnet_features
from backend.ml.anomaly import (
    _get_connection_velocity_per_ip, _get_port_scan_indicator,
    _get_exfiltration_indicator, _get_beaconing_indicator, _get_dns_query_pattern,
    _get_dns_tunnel_indicator, _get_dns_long_label_indicator,
    _get_protocol_anomaly_score, _get_tls_https_ratio,
    _get_connection_diversity_score, _get_data_volume_asymmetry,
    _get_connection_regularity_score, _get_outbound_connection_ratio,
)
net_by_ip = dd(list)
for r in net_rows: net_by_ip[r.remote_ip or "unknown"].append(r)
network_X, network_rows_out = [], []
for ip, rows in net_by_ip.items():
    cnt = len(rows)
    dports = len(set(r.remote_port or 0 for r in rows))
    bsent = sum(r.bytes_sent or 0 for r in rows)
    brecv = sum(r.bytes_recv or 0 for r in rows)
    dur = sum(r.duration_seconds or 0 for r in rows) / 3600.0
    sm, rm = bsent/1e6, brecv/1e6
    rate = sm / max(dur, 0.01)
    # 34-dim feature vector matching score_network_connection and _load_network_features
    subnet_feats = _ip_subnet_features(ip)  # 8
    flow_feats = [float(cnt), float(dports), sm, rm, dur, rate]  # 6
    enhanced_feats = [  # 5
        _get_connection_velocity_per_ip(session, ip, 60),
        _get_port_scan_indicator(session, ip, 60),
        _get_exfiltration_indicator(session, ip, 1),
        _get_beaconing_indicator(session, ip, 1),
        _get_dns_query_pattern(session, 1),
    ]
    is_attack_ip = 1.0 if is_attack_ip_offline(ip) else 0.0
    temporal_feats = [  # 5
        min(_get_connection_velocity_per_ip(session, ip, 5), 2.0),
        0.5,
        is_attack_ip,
        min(float(cnt) / max(dur * 60.0, 1.0), 2.0),
        min(_get_port_scan_indicator(session, ip, 15), 2.0),
    ]
    v7_net_feats = [  # 8
        _get_dns_tunnel_indicator(session, 1),
        _get_dns_long_label_indicator(session, 1),
        _get_protocol_anomaly_score(session, ip, dports),
        _get_tls_https_ratio(session, 1),
        _get_connection_diversity_score(session, 1),
        _get_data_volume_asymmetry(session, ip, 1),
        _get_connection_regularity_score(session, ip, 1),
        _get_outbound_connection_ratio(session, 1),
    ]
    vec = subnet_feats + flow_feats + enhanced_feats + temporal_feats + v7_net_feats + [is_attack_ip, 0.0]
    network_X.append(vec[:34])
    network_rows_out.append({"remote_ip": ip})
network_X = np.array(network_X, dtype=float)
network_y = np.array([1 if is_attack_ip_offline(r.remote_ip or "unknown") else 0 for r in network_rows_out], dtype=int)
print(f"  Network: {network_X.shape} pos={int(network_y.sum())}", flush=True)

print(f"\n[{time.time()-t0:.0f}s] Training...", flush=True)
new_models, new_thresholds, stream_X, stream_y = {}, dict(_DEFAULT_THRESHOLDS), {}, {}
for beh, X, y in [("login",login_X,login_y),("process",process_X,process_y),("network",network_X,network_y)]:
    if len(X)<3: continue
    m = IsolationForest(contamination=ML_CONTAMINATION, random_state=ML_RANDOM_STATE, n_estimators=100, max_samples=min(256,len(X)))
    m.fit(X)
    new_models[beh] = m; stream_X[beh]=X; stream_y[beh]=y
    print(f"  {beh}: IF ({len(X)})", flush=True)

detector = get_detector()
new_sup = {}
for beh in ("login","process","network"):
    X, y = stream_X.get(beh), stream_y.get(beh)
    if X is None or len(X)<4: continue
    atk, ben = X[y.astype(bool)], X[~y.astype(bool)]
    if len(atk)<3 or len(ben)<3: continue
    X_all = np.vstack([ben,atk])
    y_all = np.array([0]*len(ben)+[1]*len(atk))
    model, name = detector._build_classifier(X_all, y_all)
    new_sup[beh] = model
    print(f"  {beh}: {name} (atk={len(atk)} ben={len(ben)})", flush=True)

# Threshold tuning (sample if too large)
for beh in new_models:
    X, y = stream_X[beh], stream_y.get(beh)
    if len(X) > 5000:
        rng = np.random.RandomState(42)
        idx = rng.choice(len(X), 5000, replace=False)
        Xs, ys = X[idx], y[idx] if y is not None else None
    else:
        Xs, ys = X, y
    t, b = detector._tune_threshold(new_models[beh], Xs, ys, supervised=new_sup.get(beh))
    new_thresholds[beh] = t
    print(f"  {beh}: threshold={t:.4f}", flush=True)

detector.models = new_models
detector.thresholds = new_thresholds
detector.supervised_by_stream = new_sup
detector.supervised_name = "+".join(new_sup.keys()) or "none"
detector.n_samples = int(len(login_X)+len(process_X)+len(network_X))
detector.trained_at = datetime.now(UTC).isoformat()
detector.events_at_train = len(events)
detector.version += 1
detector._save_meta()
detector._save_bundle()
total = time.time()-t0
print(f"\n{'='*50}", flush=True)
print(f"DONE in {total:.0f}s ({total/60:.1f} min)", flush=True)
print(f"Version: {detector.version} | Samples: {detector.n_samples} | Events: {len(events)}", flush=True)
print(f"Streams: {list(new_models.keys())} | Supervised: {list(new_sup.keys())}", flush=True)
print(f"Thresholds: {new_thresholds}", flush=True)
