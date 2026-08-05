"""Machine Learning module - lightweight anomaly detection (Upgrade Module 4).

Per-behavior anomaly analysis with three lightweight models, all small and
fast enough for a single Windows 11 laptop:

1. Isolation Forest - one detector per behavior stream (login / process /
   network); flags events that deviate from the locally learned baseline.
2. Random Forest / XGBoost - supervised classifier distinguishing baseline
   activity from simulated attack events; acts as a second opinion and for
   drift monitoring. XGBoost is used when installed; otherwise a scikit-learn
   gradient boosting fallback is used.
3. Per-event anomaly scoring (0-1) feeds the Hybrid Risk Scoring Engine.

Trained on data present in the local database; no data leaves the machine.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import func, select

from backend.config import ML_CONTAMINATION, ML_RANDOM_STATE, ML_TRAIN_MIN_SAMPLES
from backend.database.connection import SessionLocal
from backend.database.models import NetworkConnection, NormalizedEvent, ProcessRecord

logger = logging.getLogger("sentinel.ml")

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

try:
    from xgboost import XGBClassifier

    HAS_XGBOOST = True
except ImportError:  # pragma: no cover
    HAS_XGBOOST = False

BEHAVIOR_KEYS = ("login", "process", "network")

# Event IDs mapped to the behavior stream they belong to.
LOGIN_EVENTS = {4624, 4625, 4634, 4647, 4648, 4740, 4771}
PROCESS_EVENTS = {4688, 4720, 4726, 4732, 7045, 4698, 4104, 4103}
NETWORK_EVENTS = set()


def _behavior_of(event_id: int) -> str:
    if event_id in LOGIN_EVENTS:
        return "login"
    if event_id in PROCESS_EVENTS:
        return "process"
    return "login"


def _fact(event, key: str, default: float = 0.0) -> float:
    """Read a numeric fact from any event shape.

    Supports ORM ``NormalizedEvent`` objects, normalized dicts (``raw_json``
    with ``facts``), and raw collector records (``raw.<key>``).
    """
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    if isinstance(raw, dict):
        facts = raw.get("facts") or {}
        if key in facts:
            try:
                return float(facts[key])
            except (TypeError, ValueError):
                return default
    if isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return default
    return default


def _bool_fact(event, key: str) -> int:
    return 1 if _fact(event, key) else 0


def _ip_feature(event, key: str) -> float:
    """Coerce an IP/status-code value into a stable numeric feature.

    Raw collectors store ``source_ip``/``sub_status`` as strings (e.g.
    ``"192.168.99.77"``, ``"0xC000006A"``), which the old code silently
    collapsed to ``0.0`` via a failed ``float()``. This returns a
    deterministic numeric sketch so the feature vector is no longer a
    near-constant. Nonexistent values map to ``0.0``.
    """
    raw = None
    try:
        raw = event.raw_json
    except AttributeError:
        raw = event.get("raw_json") if isinstance(event, dict) else None
    value = None
    if isinstance(raw, dict):
        value = (raw.get("facts") or {}).get(key)
    elif isinstance(event, dict):
        value = (event.get("raw") or {}).get(key)

    if value is None:
        return 0.0
    # Already numeric -> use directly.
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()

    def _digits(s: str) -> float:
        return sum(int(c) for c in s if c.isdigit())

    # IPv4 dotted form -> combine octets into a bounded numeric sketch.
    if "." in text and all(ch.isdigit() for ch in text.replace(".", "")):
        try:
            parts = [int(p) for p in text.split(".") if p.isdigit()]
            if len(parts) == 4:
                return float((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
        except (TypeError, ValueError, OverflowError):
            pass
    # Hex status codes -> numeric sum of digits (deterministic).
    if text.startswith("0x"):
        return float(_digits(text))
    if text.isdigit():
        return float(text)
    # Keep something signal-y rather than a silent zero.
    return float(_digits(text) or 0)


def event_feature_vector(event) -> list[float] | None:
    """Feature vector for a single event (None if the behavior stream is unknown)."""
    event_id = event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
    behavior = _behavior_of(int(event_id))
    if behavior == "login":
        return [
            int(event_id),
            _fact(event, "logon_type"),
            _ip_feature(event, "sub_status") / 100.0,
            _ip_feature(event, "source_ip") / 4_294_967_296.0,
            _bool_fact(event, "is_locked"),
        ]
    if behavior == "process":
        return [
            int(event_id),
            _bool_fact(event, "has_encoded"),
            _bool_fact(event, "has_download"),
            _bool_fact(event, "has_hidden"),
            _bool_fact(event, "group_sid") if _fact(event, "group_sid") else 0.0,
        ]
    return None


# ---------------------------------------------------------------------------
# Feature extraction (per behavior stream)
# ---------------------------------------------------------------------------
def _load_behavior_features(session, since: datetime, event_ids: set[int]) -> np.ndarray:
    """Per-event feature matrix for a behavior stream.

    Uses :func:`event_feature_vector` so training and scoring share the same
    feature space (see docs/ml_strategy_and_validation.md).
    """
    rows = session.scalars(
        select(NormalizedEvent).where(
            NormalizedEvent.event_id.in_(event_ids),
            NormalizedEvent.timestamp >= since,
        )
    ).all()
    X = []
    for ev in rows:
        features = event_feature_vector(ev)
        if features:
            X.append(features)
    return np.array(X, dtype=float) if X else np.empty((0, 5))


def _load_network_features(session, since: datetime) -> tuple[np.ndarray, list[dict]]:
    """Per-remote-IP flow features: count, distinct ports, bytes, duration.

    Returns (X, rows) where ``rows`` carries the remote_ip label for each
    feature row so the IP encoder can be retained for scoring unseen hosts.
    """
    rows = session.execute(
        select(
            NetworkConnection.remote_ip,
            func.count(NetworkConnection.id),
            func.count(func.distinct(NetworkConnection.remote_port)),
            func.sum(NetworkConnection.bytes_sent),
            func.sum(NetworkConnection.bytes_recv),
            func.avg(NetworkConnection.duration_seconds),
        )
        .where(NetworkConnection.observed_at >= since)
        .group_by(NetworkConnection.remote_ip)
    ).all()
    if not rows:
        return np.empty((0, 6)), []
    encoder = LabelEncoder()
    ips = [r[0] or "unknown" for r in rows]
    encoded = encoder.fit_transform(ips).reshape(-1, 1)
    flows = np.array(
        [
            [
                int(r[1]),
                int(r[2]),
                float(r[3] or 0),
                float(r[4] or 0),
                float(r[5] or 0),
            ]
            for r in rows
        ],
        dtype=float,
    )
    X = np.hstack([encoded, flows])
    return X, [{"remote_ip": ip} for ip in ips]


class MLAnomalyDetector:
    """Per-behavior Isolation Forest + supervised classifier wrapper."""

    def __init__(self):
        self.models: dict[str, IsolationForest] = {}
        self.supervised = None
        self.supervised_name = "none"
        self.trained_at: str | None = None
        self.n_samples = 0
        self.encoders: dict[str, LabelEncoder] = {}

    @property
    def is_ready(self) -> bool:
        return HAS_SKLEARN and bool(self.models)

    # ------------------------------------------------------------------
    def train(self, session=None, hours: int = 24) -> dict:
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        close = session is None
        session = session or SessionLocal()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            datasets = {
                "login": _load_behavior_features(session, since, LOGIN_EVENTS),
                "process": _load_behavior_features(session, since, PROCESS_EVENTS),
                "network": _load_network_features(session, since)[0],
            }
            _, network_rows = _load_network_features(session, since)

            self.models = {}
            self.encoders = {}
            trained_streams = []
            for behavior, X in datasets.items():
                if len(X) < 3:
                    continue
                model = IsolationForest(
                    contamination=ML_CONTAMINATION,
                    random_state=ML_RANDOM_STATE,
                    n_estimators=60,
                )
                model.fit(X)
                self.models[behavior] = model
                trained_streams.append(behavior)

            # Retain the ip -> code encoder so unseen connections can be scored
            # in the same feature space as the trained network model.
            if "network" in self.models and network_rows:
                encoder = LabelEncoder()
                encoder.fit([r["remote_ip"] for r in network_rows])
                self.encoders["network"] = encoder

            if not self.models:
                return {"status": "insufficient-data", "trained": False}

            self.n_samples = int(sum(len(d) for d in datasets.values()))
            if self.n_samples < ML_TRAIN_MIN_SAMPLES:
                logger.info(
                    "Only %d samples; training anyway (min %d)", self.n_samples, ML_TRAIN_MIN_SAMPLES
                )

            # Supervised layer: learn attack vs baseline clusters from history.
            attack_samples, baseline_samples = self._labeled_samples(session)
            if len(attack_samples) >= 10 and len(baseline_samples) >= 3:
                X_all = np.vstack([baseline_samples, attack_samples])
                y_all = np.array([0] * len(baseline_samples) + [1] * len(attack_samples))
                self.supervised, self.supervised_name = self._build_classifier(X_all, y_all)
            else:
                self.supervised = None
                self.supervised_name = "none"

            self.trained_at = datetime.now(timezone.utc).isoformat()
            logger.info(
                "ML models trained on %d samples; streams=%s supervised=%s",
                self.n_samples, trained_streams, self.supervised_name,
            )
            return {
                "status": "ok",
                "trained": True,
                "samples": self.n_samples,
                "streams": trained_streams,
                "supervised": self.supervised_name,
                "trained_at": self.trained_at,
            }
        finally:
            if close:
                session.close()

    @staticmethod
    def _build_classifier(X, y):
        """XGBoost when available, else sklearn gradient/random forest."""
        if HAS_XGBOOST:
            model = XGBClassifier(
                n_estimators=60, max_depth=3, learning_rate=0.1,
                random_state=ML_RANDOM_STATE, eval_metric="logloss",
            )
            model.fit(X, y)
            return model, "xgboost"
        model = RandomForestClassifier(n_estimators=50, random_state=ML_RANDOM_STATE, max_depth=4)
        model.fit(X, y)
        return model, "random_forest"

    @staticmethod
    def _labeled_samples(session) -> tuple[list[list[float]], list[list[float]]]:
        """Heuristic labels: simulated attack events vs benign baseline.

        Builds labels from the *real* feature vectors (via
        :func:`event_feature_vector`) so the supervised classifier is trained
        on the same 5-dim space used for scoring. Previously this returned
        hardcoded 3-dim vectors, which silently zeroed the classifier because
        its ``n_features_in_`` never matched the scorer.
        """
        attack_samples: list[list[float]] = []
        baseline_samples: list[list[float]] = []
        rows = session.execute(select(NormalizedEvent.raw_json, NormalizedEvent.event_id)).all()
        for raw, event_id in rows:
            facts = (raw or {}).get("facts", {})
            src = str(facts.get("source_ip", "") or "")
            eid = int(event_id)
            if eid == 4625 and (src.startswith("192.168.99") or src.startswith("10.")):
                is_attack = True
            elif eid in (4624, 4634, 4647, 4771):  # benign logon family
                is_attack = False
            elif eid in (4720, 4732, 7045, 4698, 4104, 4103, 4688):  # risky mutation
                is_attack = True
            else:
                is_attack = bool(facts.get("is_anomalous") or facts.get("attack"))
            features = event_feature_vector({"event_id": eid, "raw_json": raw})
            if not features:
                continue
            (attack_samples if is_attack else baseline_samples).append(features)
        return attack_samples, baseline_samples

    # ------------------------------------------------------------------
    def _combined_score(self, model, features: list[float]) -> float:
        """Blend the IsolationForest anomaly signal with the supervised
        classifier's attack probability into a single [0,1] score."""
        base = self._score_with(model, features)
        if self.supervised is None:
            return base
        p = self.supervised_proba(features)
        return float(max(0.0, min(1.0, 0.6 * base + 0.4 * p)))

    def score_event(self, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Uses the login model for backward compatibility (generic callers),
        falling back to the first available behavior model.
        """
        if not self.is_ready:
            return 0.0
        model = self.models.get("login") or next(iter(self.models.values()))
        return self._combined_score(model, features)

    def score_event_for_behavior(self, behavior: str, features: list[float]) -> float:
        model = self.models.get(behavior)
        if model is None:
            return 0.0
        return self._combined_score(model, features)

    def score_network_connection(
        self,
        remote_ip: str,
        count: int = 1,
        distinct_ports: int = 1,
        bytes_sent: int = 0,
        bytes_recv: int = 0,
        duration: float = 0.0,
    ) -> float:
        """Anomaly score for an aggregated remote-IP flow bucket.

        Feature vector: [ip_code, count, distinct_ports, bytes_sent,
        bytes_recv, duration_seconds].
        """
        model = self.models.get("network")
        encoder = self.encoders.get("network")
        if model is None or encoder is None:
            return 0.0
        if remote_ip in encoder.classes_:
            code = float(encoder.transform([remote_ip])[0])
        else:
            code = -1.0  # unseen host -> treat as novel
        return self._combined_score(
            model,
            [code, float(count), float(distinct_ports), float(bytes_sent), float(bytes_recv), float(duration)],
        )

    @staticmethod
    def _score_with(model, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Uses the IsolationForest ``decision_function``: normal points score
        above 0 and anomalies below 0, so ``0.5 - decision`` maps the decision
        boundary onto 0.5 (matches sklearn's ``predict`` semantics).
        """
        arr = np.array([features], dtype=float)
        if arr.shape[1] != model.n_features_in_:
            return 0.0
        decision = float(model.decision_function(arr)[0])
        return float(max(0.0, min(1.0, 0.5 - decision)))

    # ------------------------------------------------------------------
    def analyze_events(self, session=None, hours: int = 1) -> dict:
        """Score recent events per behavior stream and mark outliers."""
        if not self.is_ready:
            return {"status": "not-ready"}

        close = session is None
        session = session or SessionLocal()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)
            events = session.scalars(
                select(NormalizedEvent).where(NormalizedEvent.timestamp >= since)
            ).all()
            flagged = 0
            scored = 0
            for ev in events:
                behavior = _behavior_of(ev.event_id)
                model = self.models.get(behavior)
                if model is None:
                    continue
                features = event_feature_vector(ev)
                if features is None:
                    continue
                try:
                    score = self._combined_score(model, features)
                except Exception:  # noqa: BLE001
                    continue
                ev.ml_score = round(score, 4)
                scored += 1
                if score > 0.5:
                    ev.is_anomaly = True
                    flagged += 1

            # Score network connection buckets in the same pass.
            if "network" in self.models:
                net_rows = session.execute(
                    select(
                        NetworkConnection.remote_ip,
                        func.count(NetworkConnection.id),
                        func.count(func.distinct(NetworkConnection.remote_port)),
                        func.sum(NetworkConnection.bytes_sent),
                        func.sum(NetworkConnection.bytes_recv),
                        func.avg(NetworkConnection.duration_seconds),
                    )
                    .where(NetworkConnection.observed_at >= since)
                    .group_by(NetworkConnection.remote_ip)
                ).all()
                for remote_ip, count, distinct_ports, bytes_sent, bytes_recv, duration in net_rows:
                    try:
                        score = self.score_network_connection(
                            remote_ip or "unknown",
                            int(count),
                            int(distinct_ports),
                            int(bytes_sent or 0),
                            int(bytes_recv or 0),
                            float(duration or 0.0),
                        )
                    except Exception:  # noqa: BLE001
                        continue
                    scored += 1
                    if score > 0.5:
                        flagged += 1

            session.commit()
            return {"status": "ok", "scored": scored, "flagged": flagged}
        finally:
            if close:
                session.close()

    # ------------------------------------------------------------------
    def supervised_proba(self, features: list[float]) -> float:
        """P(attack) from the supervised classifier, or 0.0 when untrained."""
        if self.supervised is None:
            return 0.0
        arr = np.array([features], dtype=float)
        if arr.shape[1] != self.supervised.n_features_in_:
            return 0.0
        proba = self.supervised.predict_proba(arr)[0]
        return float(proba[1] if len(proba) > 1 else 0.0)

    def status(self) -> dict:
        return {
            "has_sklearn": HAS_SKLEARN,
            "has_xgboost": HAS_XGBOOST,
            "ready": self.is_ready,
            "trained_at": self.trained_at,
            "samples": self.n_samples,
            "streams": list(self.models.keys()),
            "supervised": self.supervised_name,
        }


_detector: MLAnomalyDetector | None = None


def get_detector() -> MLAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = MLAnomalyDetector()
    return _detector
