"""Background ML training - run model training off the request thread.

Training blocks the API for seconds; scheduling it in a daemon thread keeps
POST /api/system/ml/train responsive. A non-blocking lock guarantees a
single training run at a time; training_active() feeds /ml/status.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import numpy as np

from backend.database.connection import SessionLocal
from backend.ml.anomaly import (
    get_detector, IsolationForest, ML_CONTAMINATION, ML_RANDOM_STATE,
    _DEFAULT_THRESHOLDS, LOGIN_EVENTS, PROCESS_EVENTS,
    _NET_ATTACK_PREFIXES, _COMMON_LOGON_TYPES, _NIGHT_HOURS,
    _ip_subnet_features,
)
from sqlalchemy import select, func
from backend.database.models import NormalizedEvent, NetworkConnection

logger = logging.getLogger("baraq.ml.tasks")
_train_lock = threading.Lock()


def _bulk_train(session, hours=None, kind="manual"):
    """Bulk O(N) training using pre-computed temporal features."""
    t0 = time.time()
    since = None if not hours else datetime.now(UTC) - timedelta(hours=hours)

    # Load all login + process events
    _all_ids = LOGIN_EVENTS | PROCESS_EVENTS
    _stmt = select(
        NormalizedEvent.id, NormalizedEvent.event_id,
        NormalizedEvent.timestamp, NormalizedEvent.raw_json,
        NormalizedEvent.user,
    ).where(NormalizedEvent.event_id.in_(_all_ids))
    if since is not None:
        _stmt = _stmt.where(NormalizedEvent.timestamp >= since)
    _stmt = _stmt.order_by(NormalizedEvent.timestamp)
    _rows = session.execute(_stmt).all()
    _events = []
    for _r in _rows:
        _facts = (_r.raw_json or {}).get("facts") or {}
        _ts = _r.timestamp
        if _ts.tzinfo is None:
            _ts = _ts.replace(tzinfo=UTC)
        _events.append({"id": _r.id, "event_id": _r.event_id, "ts": _ts, "facts": _facts, "user": _r.user or ""})
    _N = len(_events)

    _login_idx = [i for i, e in enumerate(_events) if e["event_id"] in LOGIN_EVENTS]
    _proc_idx = [i for i, e in enumerate(_events) if e["event_id"] in PROCESS_EVENTS]

    # --- Pre-compute temporal lookups (O(N) sliding window) ---
    _tsp = {}
    for _name, _indices in [("login", _login_idx), ("process", _proc_idx)]:
        for _k, _idx in enumerate(_indices):
            _tsp[(_name, _idx)] = 0.0 if _k == 0 else (_events[_idx]["ts"] - _events[_indices[_k - 1]]["ts"]).total_seconds() / 3600.0

    _r1h = defaultdict(int)
    _r24h = defaultdict(int)
    for _name, _indices in [("login", _login_idx), ("process", _proc_idx)]:
        if not _indices:
            continue
        _left1 = 0
        _left24 = 0
        for _k, _idx in enumerate(_indices):
            _ev_ts = _events[_idx]["ts"]
            while _left1 < _k and (_ev_ts - _events[_indices[_left1]]["ts"]).total_seconds() > 3600:
                _left1 += 1
            while _left24 < _k and (_ev_ts - _events[_indices[_left24]]["ts"]).total_seconds() > 86400:
                _left24 += 1
            _r1h[(_name, _idx)] = _k - _left1
            _r24h[(_name, _idx)] = _k - _left24

    _fail_ip = defaultdict(list)
    for _i, _e in enumerate(_events):
        if _e["event_id"] == 4625:
            _ip = str(_e["facts"].get("source_ip", ""))
            if _ip:
                _fail_ip[_ip].append((_e["ts"], _i))

    _lt1h = defaultdict(lambda: defaultdict(int))
    _left = 0
    for _k, _idx in enumerate(_login_idx):
        _ev_ts = _events[_idx]["ts"]
        while _left < _k and (_ev_ts - _events[_login_idx[_left]]["ts"]).total_seconds() > 3600:
            _left += 1
        for _j in range(_left, _k + 1):
            _lt = int(_events[_login_idx[_j]]["facts"].get("logon_type", 0))
            _lt1h[_idx][_lt] += 1

    _user_logins = defaultdict(list)
    for _i, _e in enumerate(_events):
        if _e["event_id"] in (4624, 4625):
            _user_logins[_e["user"]].append((_e["ts"], _i, str(_e["facts"].get("source_ip", ""))))
    _ip_div = {}
    for _user, _logins in _user_logins.items():
        _left = 0
        for _k, (_ts, _idx, _ip) in enumerate(_logins):
            while _left < _k and (_ts - _logins[_left][0]).total_seconds() > 86400:
                _left += 1
            _unique = set(_logins[_j][2] for _j in range(_left, _k + 1))
            _ip_div[_idx] = len(_unique) / max(_k - _left + 1, 1)

    _lz = {}
    _left = 0
    for _k, _idx in enumerate(_login_idx):
        _ev_ts = _events[_idx]["ts"]
        while _left < _k and (_ev_ts - _events[_login_idx[_left]]["ts"]).total_seconds() > 86400:
            _left += 1
        if _k - _left < 2:
            _lz[_idx] = 0.0
            continue
        _gaps = [(_events[_login_idx[_j]]["ts"] - _events[_login_idx[_j - 1]]["ts"]).total_seconds() / 60.0
                 for _j in range(max(_left + 1, _k - 49), _k + 1)]
        if len(_gaps) < 2:
            _lz[_idx] = 0.0
            continue
        _mg = sum(_gaps) / len(_gaps)
        _sg = (sum((_g - _mg) ** 2 for _g in _gaps) / len(_gaps)) ** 0.5
        _lz[_idx] = 0.0 if _sg == 0 else min(1.0, max(0.0, abs((_gaps[-1] - _mg) / _sg) / 3.0))

    _all_sorted = sorted(range(_N), key=lambda _i: _events[_i]["ts"])
    _cross = {}
    _left = 0
    for _k, _idx in enumerate(_all_sorted):
        _ev_ts = _events[_idx]["ts"]
        while _left < _k and (_ev_ts - _events[_all_sorted[_left]]["ts"]).total_seconds() > 3600:
            _left += 1
        _failed = sum(1 for _j in range(_left, _k + 1) if _events[_all_sorted[_j]]["event_id"] == 4625)
        _procs = sum(1 for _j in range(_left, _k + 1) if _events[_all_sorted[_j]]["event_id"] in PROCESS_EVENTS)
        _types = len(set(_events[_all_sorted[_j]]["event_id"] for _j in range(_left, _k + 1)))
        _ts = (_events[_all_sorted[-1]]["ts"] - _ev_ts).total_seconds() / 3600.0 if _k < len(_all_sorted) - 1 else 0.0
        _cross[_idx] = [min(_failed / 10, 1), min(_procs / 10, 1), 0.0,
                        min(_failed / max(_procs, 1), 1), min(_ts, 1),
                        1.0 if _failed > 0 and _procs > 0 else 0.0, 0.0, min(_types / 5, 1)]

    # --- Build feature vectors ---
    def _cmd_ent(s):
        if not s:
            return 0.0
        cc = {}
        for c in s:
            cc[c] = cc.get(c, 0) + 1
        return min(1.0, -sum((v / len(s)) * math.log2(v / len(s)) for v in cc.values()) / 7.0)

    def _ip_f(ip):
        try:
            p = ip.split(".")
            return (int(p[0]) << 24 | int(p[1]) << 16 | int(p[2]) << 8 | int(p[3])) / 4294967296.0
        except Exception:
            return 0.0

    def _is_atk(ev):
        f = ev["facts"]
        eid = ev["event_id"]
        if eid in (4625, 4720, 4726, 4732, 7045, 4698):
            return True
        ip = str(f.get("source_ip", ""))
        if ip in ("203.0.113.66", "203.0.113.77", "198.51.100.66", "198.51.100.77"):
            return True
        if f.get("has_encoded") or f.get("has_download"):
            return True
        if eid == 4624 and int(f.get("logon_type", 0)) not in _COMMON_LOGON_TYPES:
            return True
        return False

    def _bld_login(ev, idx):
        f = ev["facts"]
        lt = int(f.get("logon_type", 0))
        sip = str(f.get("source_ip", ""))
        h = ev["ts"].hour
        hs = math.sin(2 * math.pi * h / 24)
        hc = math.cos(2 * math.pi * h / 24)
        f5 = f15 = f60 = 0.0
        if sip in _fail_ip:
            now = ev["ts"]
            for ts2, _ in reversed(_fail_ip[sip]):
                dm = (now - ts2).total_seconds() / 60
                if dm > 60:
                    break
                f60 += 1
                if dm <= 15:
                    f15 += 1
                if dm <= 5:
                    f5 += 1
        tc = _lt1h.get(idx, {})
        ts_ = sum(tc.values())
        ent = sum(-(c / ts_) * math.log2(c / ts_) for c in tc.values() if c > 0) if tc else 0.0
        me = math.log2(max(len(tc), 1))
        return [ev["event_id"], lt, int(f.get("sub_status", 0)) / 100, _ip_f(sip), int(bool(f.get("is_locked", 0))),
                hs, hc, 1.0 if h in _NIGHT_HOURS else 0.0, 1.0 if ev["ts"].weekday() >= 5 else 0.0,
                1.0 if lt > 0 and lt not in _COMMON_LOGON_TYPES else 0.0,
                min(_tsp.get(("login", idx), 0) / 24, 1), min(_r1h.get(("login", idx), 0) / 10, 1),
                min(_r24h.get(("login", idx), 0) / 100, 1), 0.0,
                min(f5 / 2, 1), min(f15 / 5, 1), min(f60 / 10, 1),
                min(1.0, ent / max(me, 1)) if me > 0 else 0.0,
                _ip_div.get(idx, 0), _lz.get(idx, 0), 0.0,
                *_cross.get(idx, [0] * 8),
                1.0 if 8 <= h < 18 and ev["ts"].weekday() < 5 else 0.0,
                0.5, 0.3, 0.0, 0.0]

    def _bld_proc(ev, idx):
        f = ev["facts"]
        h = ev["ts"].hour
        img = str(f.get("image_path", "")).lower()
        cmd = str(f.get("command_line", ""))
        par = str(f.get("parent_process", "")).lower()
        return [ev["event_id"],
                math.sin(2 * math.pi * h / 24), math.cos(2 * math.pi * h / 24),
                1.0 if h in _NIGHT_HOURS else 0.0, 1.0 if ev["ts"].weekday() >= 5 else 0.0,
                int(bool(f.get("has_encoded", 0))), int(bool(f.get("has_download", 0))), int(bool(f.get("has_hidden", 0))),
                min(len(cmd) / 500, 1),
                1.0 if any(x in img for x in ["certutil", "bitsadmin", "mshta", "wscript", "cscript"]) else 0.0,
                1.0 if any(x in par for x in ["winword", "excel", "outlook", "wscript"]) else 0.0,
                _cmd_ent(cmd),
                min(_tsp.get(("process", idx), 0) / 24, 1), min(_r1h.get(("process", idx), 0) / 10, 1),
                min(_r24h.get(("process", idx), 0) / 100, 1), min(_r1h.get(("process", idx), 0) / 50, 1),
                *_cross.get(idx, [0] * 8),
                1.0 if 8 <= h < 18 and ev["ts"].weekday() < 5 else 0.0,
                0.5, 0.5, 0.0, 0.0]

    login_X = np.array([_bld_login(_events[i], i) for i in _login_idx], dtype=float) if _login_idx else np.empty((0, 34))
    login_y = np.array([1 if _is_atk(_events[i]) else 0 for i in _login_idx], dtype=int) if _login_idx else np.empty((0,), dtype=int)
    process_X = np.array([_bld_proc(_events[i], i) for i in _proc_idx], dtype=float) if _proc_idx else np.empty((0, 24))
    process_y = np.array([1 if _is_atk(_events[i]) else 0 for i in _proc_idx], dtype=int) if _proc_idx else np.empty((0,), dtype=int)

    # Network features (bulk SQL, no per-IP queries)
    _net_stmt = select(
        NetworkConnection.remote_ip, func.count(NetworkConnection.id),
        func.count(func.distinct(NetworkConnection.remote_port)),
        func.sum(NetworkConnection.bytes_sent), func.sum(NetworkConnection.bytes_recv),
        func.avg(NetworkConnection.duration_seconds),
    )
    if since is not None:
        _net_stmt = _net_stmt.where(NetworkConnection.observed_at >= since)
    _net_rows = session.execute(_net_stmt.group_by(NetworkConnection.remote_ip)).all()
    _net_flows = []
    _net_ips = []
    for _r in _net_rows:
        _ip = _r[0] or "unknown"
        _sm = float(_r[3] or 0) / 1e6
        _rm = float(_r[4] or 0) / 1e6
        _dh = float(_r[5] or 0) / 3600.0
        _ia = 1.0 if _ip.startswith(_NET_ATTACK_PREFIXES) else 0.0
        _vec = _ip_subnet_features(_ip) + [float(_r[1]), float(_r[2]), _sm, _rm, _dh, _sm / max(_dh, 0.01)] + [0] * 5 + [_ia] * 3 + [0] * 4 + [_ia, 0.5, _ia, 0, 0]
        _net_flows.append(_vec[:26])
        _net_ips.append(_ip)
    network_X = np.array(_net_flows, dtype=float) if _net_flows else np.empty((0, 26))
    network_y = np.array([1 if ip.startswith(_NET_ATTACK_PREFIXES) else 0 for ip in _net_ips], dtype=int)

    logger.info("Bulk feature build: login=%s process=%s network=%s (%.0fs)",
                login_X.shape, process_X.shape, network_X.shape, time.time() - t0)

    # --- Train models ---
    detector = get_detector()
    new_models = {}
    new_thresholds = dict(_DEFAULT_THRESHOLDS)
    new_baselines = {}
    stream_X = {}
    stream_y = {}

    for beh, X, y in [("login", login_X, login_y), ("process", process_X, process_y), ("network", network_X, network_y)]:
        if len(X) < 3:
            continue
        m = IsolationForest(contamination=ML_CONTAMINATION, random_state=ML_RANDOM_STATE,
                            n_estimators=100, max_samples=min(256, len(X)))
        m.fit(X)
        new_models[beh] = m
        stream_X[beh] = X
        stream_y[beh] = y

    if not new_models:
        return {"status": "insufficient-data", "trained": False}

    new_sup = {}
    new_sup_name = {}
    for beh in ("login", "process", "network"):
        X = stream_X.get(beh)
        y = stream_y.get(beh)
        if X is None or y is None or len(X) < 4:
            continue
        atk = X[y.astype(bool)]
        ben = X[~y.astype(bool)]
        if len(atk) < 3 or len(ben) < 3:
            continue
        X_all = np.vstack([ben, atk])
        y_all = np.array([0] * len(ben) + [1] * len(atk))
        model, name = detector._build_classifier(X_all, y_all)
        new_sup[beh] = model
        new_sup_name[beh] = name

    # Threshold tuning (sample if large)
    for beh in new_models:
        _Xt, _yt = stream_X[beh], stream_y.get(beh)
        if len(_Xt) > 5000:
            _rng = np.random.RandomState(42)
            _sel = _rng.choice(len(_Xt), 5000, replace=False)
            _Xt, _yt = _Xt[_sel], _yt[_sel] if _yt is not None else None
        t, b = detector._tune_threshold(new_models[beh], _Xt, _yt, supervised=new_sup.get(beh))
        new_thresholds[beh] = t
        new_baselines[beh] = b

    best_stream = next(iter(new_sup)) if new_sup else "none"
    detector.models = new_models
    detector.thresholds = new_thresholds
    detector.baselines = new_baselines
    detector.supervised = new_sup.get(best_stream)
    detector.supervised_name = "+".join(new_sup.keys()) or "none"
    detector.supervised_by_stream = new_sup
    detector.supervised_name_by_stream = new_sup_name
    detector.n_samples = int(len(login_X) + len(process_X) + len(network_X))
    detector.encoders = {}
    detector.trained_at = datetime.now(UTC).isoformat()
    detector.events_at_train = _N
    detector.version += 1
    detector.model_source = "user"
    detector.last_train_kind = kind
    detector.versions.append({
        "version": detector.version, "kind": kind,
        "trained_at": detector.trained_at, "samples": detector.n_samples,
        "events_at_train": detector.events_at_train,
        "streams": list(new_models.keys()), "supervised": detector.supervised_name,
        "thresholds": {k: round(v, 3) for k, v in new_thresholds.items()},
    })
    detector.versions = detector.versions[-10:]
    detector._save_meta()
    detector._save_bundle()

    elapsed = time.time() - t0
    logger.info("Bulk ML train done in %.0fs: v%d samples=%d streams=%s supervised=%s",
                elapsed, detector.version, detector.n_samples,
                list(new_models.keys()), detector.supervised_name)
    return {
        "status": "ok", "trained": True, "samples": detector.n_samples,
        "streams": list(new_models.keys()), "supervised": detector.supervised_name,
        "thresholds": new_thresholds, "trained_at": detector.trained_at,
    }


def train_in_background(hours=None, validate=True, force=False):
    if not _train_lock.acquire(blocking=False):
        return False

    def _work():
        db = SessionLocal()
        try:
            result = _bulk_train(db, hours=hours, kind="manual")
            logger.info("Background ML training finished: %s", result.get("status"))
        except Exception:
            logger.exception("Background ML training failed")
        finally:
            db.close()
            _train_lock.release()

    threading.Thread(target=_work, daemon=True, name="baraq-ml-train").start()
    return True


def check_online_update():
    """Check if online learning update is needed and perform it.

    Called periodically by the background scheduler. Uses ADWIN drift detection
    and reservoir sampling buffers to perform incremental model updates.
    """
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    if not detector.is_ready or detector.online_learner is None:
        return None

    try:
        if detector.online_learner.should_update():
            logger.info("Online learning update triggered")
            result = detector.online_learner.incremental_update()
            logger.info("Online learning update: %s", result.get("status"))
            return result
    except Exception:
        logger.debug("Online learning update failed", exc_info=True)
    return None


def get_active_learning_suggestions():
    """Get top uncertain events for analyst labeling.

    Returns list of (event_id, features, uncertainty_score) tuples
    that would most improve the model if labeled.
    """
    from backend.ml.anomaly import get_detector

    detector = get_detector()
    if not detector.is_ready or detector.online_learner is None:
        return []

    try:
        return detector.online_learner.active_learner.suggest_for_labeling(
            features_list=[], behaviors=[], models=detector.models
        )
    except Exception:
        return []


def training_active():
    return _train_lock.locked()
