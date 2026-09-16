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
    get_detector, LOGIN_EVENTS, PROCESS_EVENTS, NETWORK_EVENTS, ML_CONTAMINATION,
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
left = 0; cs_fail = 0; cs_proc = 0; cs_net = 0; cs_types = set()
for k, idx in enumerate(all_sorted):
    ev_ts = events[idx]["ts"]
    while left < k and (ev_ts - events[all_sorted[left]]["ts"]).total_seconds() > 3600:
        le = events[all_sorted[left]]
        if le["event_id"] == 4625: cs_fail -= 1
        if le["event_id"] in PROCESS_EVENTS: cs_proc -= 1
        if le["event_id"] in NETWORK_EVENTS: cs_net -= 1
        cs_types.discard(le["event_id"])
        left += 1
    cur = events[idx]["event_id"]
    if cur == 4625: cs_fail += 1
    if cur in PROCESS_EVENTS: cs_proc += 1
    if cur in NETWORK_EVENTS: cs_net += 1
    cs_types.add(cur)
    _ts_val = (events[all_sorted[-1]]["ts"] - ev_ts).total_seconds() / 3600.0 if k < len(all_sorted) - 1 else 0.0
    cross[idx] = [min(cs_fail/10,1), min(cs_proc/10,1), min(cs_net/10,1),
                  min(cs_fail/max(cs_proc,1),1), min(_ts_val,1),
                  1.0 if cs_fail>0 and cs_proc>0 else 0.0,
                  1.0 if cs_proc>0 and cs_net>0 else 0.0,
                  min(len(cs_types)/5,1)]

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

# Pre-compute per-user stats (O(N)) for build_login
precomp_user_fail = defaultdict(int)
precomp_user_total = defaultdict(int)
precomp_user_ips = defaultdict(set)
precomp_user_hcounts = defaultdict(lambda: defaultdict(int))
precomp_ip_fail_count = defaultdict(int)
for ev in events:
    eid = ev["event_id"]
    user = ev["user"]
    sip = str(ev["facts"].get("source_ip", ""))
    if eid in (4624, 4625):
        precomp_user_total[user] += 1
        if sip: precomp_user_ips[user].add(sip)
        precomp_user_hcounts[user][ev["ts"].hour] += 1
    if eid == 4625:
        precomp_user_fail[user] += 1
        if sip: precomp_ip_fail_count[sip] += 1

# 3. Label with attack heuristic (matches _is_attack_sample v9)
from backend.ml.realworld_labeler import is_attack_ip_offline

def is_attack(ev):
    f = ev["facts"]
    eid = ev["event_id"]
    if eid in (4720, 4726, 4732, 7045, 4698): return True
    if eid in (4634, 4647, 4771): return False
    if eid == 4625:
        sub = int(f.get("sub_status", 0))
        try: sub = int(sub)
        except: sub = int(str(sub), 16) if str(sub).startswith("0x") else 0
        if sub in (3221226036, 3221225586): return True
        if sub in (3221225578, 3221225572, 3221225581): return True
        ip = str(f.get("source_ip", ""))
        if ip and ip != "-" and is_attack_ip_offline(ip): return True
        lt = int(f.get("logon_type", 0))
        if lt in (3, 4, 5, 8, 10) and sub != 0: return True
        return False
    if eid == 4624:
        tu = str(f.get("target_user", "")).lower()
        if tu in ("system", "local service", "network service"): return True
        lp = str(f.get("logon_process", "") or "")
        if lp and lp not in ("NtLmSsp", "Kerberos", "Negotiate", "WDIGEST", "MSSECRPC"): return True
        lt = int(f.get("logon_type", 0))
        if lt in (4, 5, 7, 8, 9, 10, 11): return True
        ip = str(f.get("source_ip", ""))
        if ip and ip != "-" and is_attack_ip_offline(ip): return True
        return False
    if eid in (1, 10, 11, 13, 17, 19, 23, 25, 4688):
        image = str(f.get("image_path", "") or f.get("new_process", "") or f.get("target_image", "") or "").lower()
        parent = str(f.get("parent_process", "") or "").lower()
        cmd = str(f.get("command_line", "") or "").lower()
        risk_names = ("mimikatz", "psexec", "nc.exe", "ncat", "netcat", "meterpreter", "cobaltstrike", "lazagne", "procdump", "sharpdump", "rubeus", "seatbelt", "sharpup", "purplesharp")
        if any(r in image for r in risk_names): return True
        lolbins = ("mshta", "wscript", "cscript", "regsvr32", "rundll32", "msbuild")
        is_lolbin = any(l in image for l in lolbins)
        is_system = any(p in image for p in ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\program files\\"))
        if is_lolbin and not is_system: return True
        if any(p in parent for p in ("winword", "excel", "outlook")) and any(x in image for x in ("powershell", "cmd", "wscript", "mshta", "cscript")): return True
        if "powershell" in image and any(x in cmd for x in ("-enc", "-encodedcommand", "frombase64", "invoke-expression", "iex")): return True
        if "powershell" in parent and any(c in image for c in ("certutil", "bitsadmin")): return True
        suspicious_cmds = ("invoke-expression", "iex(", "downloadstring", "invoke-webrequest", "certutil -decode", "reg save", "lsass", "sekurlsa", "kerberos::list", "misc::skeleton")
        if any(s in cmd for s in suspicious_cmds): return True
        if eid == 10:
            granted = str(f.get("granted_access", "")).lower()
            if "lsass" in image and granted in ("0x1010", "0x1410", "0x1438", "0x1038", "0x1fffff"): return True
            if any(t in image for t in ("lsass", "sekurlsa")): return True
        return False
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
    sub = int(f.get("sub_status",0))
    try: sub = int(sub)
    except: sub = int(str(sub), 16) if str(sub).startswith("0x") else 0
    lp = str(f.get("logon_process","") or "").lower()
    auth = 0.7 if "ntlm" in lp else (0.1 if "kerberos" in lp else 0.5)
    tip = 0.0
    if sip:
        if sip.startswith(("203.0.113.", "198.51.100.", "192.0.2.")): tip = 0.9
        elif sip in ("203.0.113.66","203.0.113.77","198.51.100.66","198.51.100.77"): tip = 0.85
        elif sip.startswith("10.") or sip.startswith("192.168."): tip = 0.1
        else: tip = 0.4
    _r1 = r1h.get(idx,0); _r24 = r24h.get(idx,0)
    burst = min(_r1 / max(_r24 / 24.0, 0.01), 2.0) if _r24 > 0 else (1.0 if _r1 > 0 else 0.0)
    kc = 0.0 if ev["event_id"]==4624 else (0.25 if ev["event_id"]==4625 else (0.5 if ev["event_id"] in (4740,4648) else 0.0))
    user = ev["user"]
    u_fail = precomp_user_fail[user]
    u_total = precomp_user_total[user]
    fs_ratio = u_fail / max(u_total, 1)
    dist_ips = min(1.0, len(precomp_user_ips[user]) / 10.0)
    u_hcounts = precomp_user_hcounts[user]
    u_htotal = sum(u_hcounts.values())
    u_hent = sum(-(c/u_htotal)*math.log2(c/u_htotal) for c in u_hcounts.values() if c>0) if u_hcounts else 0.0
    u_hmax = math.log2(max(len(u_hcounts),1))
    hdist = min(1.0, u_hent / max(u_hmax,1)) if u_hmax > 0 else 0.0
    ip_fail = precomp_ip_fail_count.get(sip, 0)
    return [lt, sub/3221226036.0, ip_f(sip),
            int(bool(f.get("is_locked",0))),
            math.sin(2*math.pi*h/24), math.cos(2*math.pi*h/24),
            1.0 if h in _NIGHT_HOURS else 0.0, 1.0 if ev["ts"].weekday()>=5 else 0.0,
            1.0 if lt>0 and lt not in _COMMON_LOGON_TYPES else 0.0,
            min(tsp.get(idx,0)/24,1), min(r1h.get(idx,0)/10,1),
            min(r24h.get(idx,0)/100,1), tip,
            0.0, 0.0, 0.0,
            0.0, 0.0, 0.0, min(ip_fail/20.0,1.0),
            *cross.get(idx,[0]*8),
            1.0 if 8<=h<18 and ev["ts"].weekday()<5 else 0.0,
            burst, kc, fs_ratio, hdist,
            auth, dist_ips, min(r1h.get(idx,0)/5,1.0), min(r24h.get(idx,0)/50,1.0)]

def build_process(ev, idx):
    f = ev["facts"]; h = ev["ts"].hour
    img = str(f.get("image_path","")).lower(); cmd = str(f.get("command_line",""))
    par = str(f.get("parent_process","")).lower()
    pe = cmd_ent(img) if img else 0.0
    sysdir = 1.0 if "system32" in img or "syswow64" in img else (0.5 if "windows" in img else 0.0)
    prisk = 0.9 if any(x in par for x in ["powershell","cmd","wscript","cscript","mshta"]) else (0.6 if any(x in par for x in ["winword","excel","outlook"]) else 0.3)
    ctokens = min(1.0, len(cmd.split()) / 30.0) if cmd else 0.0
    cmd_lower = cmd.lower()
    enc_cmd = 1.0 if any(x in cmd_lower for x in ("-enc", "-encodedcommand", "frombase64")) else 0.0
    dl_cmd = 1.0 if any(x in cmd_lower for x in ("invoke-webrequest", "curl", "wget", "downloadstring", "bitsadmin")) else 0.0
    atk_tool = 1.0 if any(x in img for x in ("mimikatz", "psexec", "rubeus", "seatbelt", "procdump", "purplesharp", "lazagne", "sharpup")) else 0.0
    office_parent = 1.0 if any(x in par for x in ("winword", "excel", "outlook")) else 0.0
    is_lsass = 1.0 if "lsass" in img else 0.0
    cmd_has_ps = 1.0 if "powershell" in img and cmd else 0.0
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
            pe, sysdir, prisk, ctokens, 0.0,
            1.0 if any(x in img for x in ("\\downloads\\", "\\appdata\\", "\\temp\\", "\\\\")) else 0.0,
            1.0 if "\\\\users\\\\" in img else 0.0,
            enc_cmd, dl_cmd, atk_tool, office_parent, is_lsass, cmd_has_ps]

# 4. Build matrices
login_X = np.array([build_login(events[i], i) for i in login_idx], dtype=float) if login_idx else np.empty((0,37))
login_y = np.array([1 if is_attack(events[i]) else 0 for i in login_idx], dtype=int) if login_idx else np.empty((0,),dtype=int)
proc_X = np.array([build_process(events[i], i) for i in proc_idx], dtype=float) if proc_idx else np.empty((0,38))
proc_y = np.array([1 if is_attack(events[i]) else 0 for i in proc_idx], dtype=int) if proc_idx else np.empty((0,),dtype=int)

# Network (per-event features from ALL events, 113K+ samples)
net_X, net_metas = _load_network_features(db, None)
from backend.ml.realworld_labeler import is_attack_ip_offline
net_y = np.array([
    1 if (
        (is_attack_ip_offline(str(r.get("remote_ip",""))) and r.get("remote_ip",""))
        or (is_attack_ip_offline(str(r.get("source_ip",""))) and r.get("source_ip",""))
        or (int(r.get("eid",0)) in (3,22,5156,5157,5158) and (r.get("remote_ip","") or r.get("source_ip","")))
    ) else 0
    for r in net_metas
], dtype=int)

# IQR-based outlier labeling (only events with IPs)
if net_X.shape[0] > 10 and net_X.shape[1] >= 22:
    has_ip = np.array([1 if r.get("remote_ip","") or r.get("source_ip","") else 0 for r in net_metas], dtype=bool)
    ip_idx = np.where(has_ip)[0]
    if len(ip_idx) > 10:
        feat_cols = net_X[ip_idx][:, [17, 18, 19, 20, 23, 24]]
        q25 = np.percentile(feat_cols, 25, axis=0)
        q75 = np.percentile(feat_cols, 75, axis=0)
        iqr = q75 - q25
        iqr[iqr < 1e-8] = 1.0
        upper = q75 + 2.0 * iqr
        for idx in ip_idx:
            if net_y[idx] == 1: continue
            vals = net_X[idx, [17, 18, 19, 20, 23, 24]]
            n_outlier = int(sum(vals > upper))
            if n_outlier >= 2: net_y[idx] = 1
            elif any(vals > q75 + 3.0 * iqr): net_y[idx] = 1

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
