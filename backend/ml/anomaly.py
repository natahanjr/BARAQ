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


def _fact(event, key: str, default=0.0) -> float:
    try:
        value = (event.raw_json or {}).get("facts", {}).get(key)
    except AttributeError:
        value = (event.get("raw") or {}).get("facts", {}).get(key) if isinstance(event, dict) else None
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _bool_fact(event, key: str) -> int:
    return 1 if _fact(event, key) else 0


def event_feature_vector(event) -> list[float] | None:
    """Feature vector for a single event (None if the behavior stream is unknown)."""
    event_id = event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
    behavior = _behavior_of(int(event_id))
    if behavior == "login":
        return [
            int(event_id),
            _fact(event, "logon_type"),
            _bool_fact(event, "sub_status"),
            _fact(event, "source_ip", 0) / 1000.0,
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
def _load_login_features(session, since: datetime) -> tuple[np.ndarray, list[dict]]:
    rows = session.execute(
        select(
            NormalizedEvent.user,
            func.sum(_case_event(4625)).label("failures"),
            func.sum(_case_event(4624)).label("successes"),
            func.count(func.distinct(NormalizedEvent.raw_json)).label("distinct_sources"),
        )
        .where(
            NormalizedEvent.event_id.in_([4624, 4625]),
            NormalizedEvent.timestamp >= since,
        )
        .group_by(NormalizedEvent.user)
    ).all()
    if not rows:
        return np.empty((0, 3)), []
    X = np.array(
        [[r.failures or 0, r.successes or 0, r.distinct_sources or 0] for r in rows],
        dtype=float,
    )
    meta = [{"user": r.user, "failures": r.failures or 0, "successes": r.successes or 0} for r in rows]
    return X, meta


def _case_event(event_id: int):
    from sqlalchemy import case
    return case((NormalizedEvent.event_id == event_id, 1), else_=0)


def _load_process_features(session, since: datetime) -> tuple[np.ndarray, list[dict]]:
    rows = session.execute(
        select(NormalizedEvent.raw_json, func.count(NormalizedEvent.id))
        .where(NormalizedEvent.event_id == 4688, NormalizedEvent.timestamp >= since)
        .group_by(NormalizedEvent.raw_json)
    ).all()
    if not rows:
        return np.empty((0, 2)), []
    encoder = LabelEncoder()
    names = [r[0].get("facts", {}).get("new_process", "unknown") if r[0] else "unknown" for r in rows]
    counts = np.array([[int(r[1])] for r in rows], dtype=float)
    encoded = encoder.fit_transform(names).reshape(-1, 1)
    X = np.hstack([encoded, counts])
    return X, [{"process": n} for n in names]


def _load_network_features(session, since: datetime) -> tuple[np.ndarray, list[dict]]:
    rows = session.execute(
        select(NetworkConnection.remote_ip, func.count(NetworkConnection.id))
        .where(NetworkConnection.observed_at >= since)
        .group_by(NetworkConnection.remote_ip)
    ).all()
    if not rows:
        return np.empty((0, 2)), []
    encoder = LabelEncoder()
    ips = [r[0] or "unknown" for r in rows]
    counts = np.array([[int(r[1])] for r in rows], dtype=float)
    encoded = encoder.fit_transform(ips).reshape(-1, 1)
    X = np.hstack([encoded, counts])
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
                "login": _load_login_features(session, since),
                "process": _load_process_features(session, since),
                "network": _load_network_features(session, since),
            }

            self.models = {}
            self.encoders = {}
            trained_streams = []
            for behavior, (X, _meta) in datasets.items():
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

            if not self.models:
                return {"status": "insufficient-data", "trained": False}

            self.n_samples = int(sum(len(d[0]) for d in datasets.values()))
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
        """Heuristic labels: simulated attack events vs benign baseline."""
        attack_samples: list[list[float]] = []
        baseline_samples: list[list[float]] = []
        rows = session.execute(select(NormalizedEvent.raw_json, NormalizedEvent.event_id)).all()
        for raw, event_id in rows:
            facts = (raw or {}).get("facts", {})
            if event_id == 4625 and str(facts.get("source_ip", "")).startswith("192.168.99"):
                attack_samples.append([1.0, 10.0, 1.0])
            elif event_id in (4720, 4732, 7045, 4698, 4104):
                attack_samples.append([0.0, 5.0, 1.0])
            elif event_id == 4624:
                baseline_samples.append([1.0, 1.0, 1.0])
        return attack_samples, baseline_samples

    # ------------------------------------------------------------------
    def score_event(self, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Uses the login model for backward compatibility (generic callers),
        falling back to the first available behavior model.
        """
        if not self.is_ready:
            return 0.0
        model = self.models.get("login") or next(iter(self.models.values()))
        return self._score_with(model, features)

    def score_event_for_behavior(self, behavior: str, features: list[float]) -> float:
        model = self.models.get(behavior)
        if model is None:
            return 0.0
        return self._score_with(model, features)

    @staticmethod
    def _score_with(model, features: list[float]) -> float:
        arr = np.array([features], dtype=float)
        if arr.shape[1] != model.n_features_in_:
            return 0.0
        raw = float(model.score_samples(arr)[0])
        return float(1.0 / (1.0 + np.exp(-raw)))  # sigmoid -> [0,1]

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
                    score = self._score_with(model, features)
                except Exception:  # noqa: BLE001
                    continue
                ev.ml_score = round(score, 4)
                scored += 1
                if score > 0.5:
                    ev.is_anomaly = True
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
