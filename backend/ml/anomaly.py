"""Machine Learning module - lightweight anomaly detection (v2).

Per-behavior anomaly analysis with a small, fast stack for a single host:

1. **Isolation Forest** - one detector per behavior stream (login / process /
   network); flags events that deviate from the locally learned baseline.
2. **Supervised second opinion** - XGBoost (or scikit-learn RandomForest
   fallback) trained on heuristically-labelled history, wrapped in
   probabilistic calibration (isotonic) when enough samples exist.
3. **Permute (rank) calibrated thresholds** - instead of a fixed 0.5, the
   anomaly score is the rank of the event within the locally-learned baseline
   CDF (a score of 0.97 means "more extreme than 97% of the training
   baseline"), and the per-stream decision boundary is tuned on that space.
   CFAR-style thresholds keep the false-alarm rate bounded even when the
   training history is entirely benign.
4. **Persistent, versioned models** - trained models are stored with joblib
   so a restart does not cold-start the detector, and a feature-version guard
   forces a clean retrain when the feature space changes.
5. **Validation gate** - when retraining with ``validate=True`` the new
   models are only adopted if they score at least as well as the current
   ones on a recent labelled window (guards against silent regressions).

Trained on data present in the local database; no data leaves the machine.
The feature space is shared between training and scoring so vectors always
agree (see docs/ml_strategy_and_validation.md).
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sqlalchemy import func, select

from backend.config import (
    ML_CONTAMINATION,
    ML_DRIFT_MIN_SAMPLES,
    ML_DRIFT_RATE,
    ML_FEATURE_VERSION,
    ML_META_FILE,
    ML_MODEL_BUNDLE,
    ML_RANDOM_STATE,
    ML_RETRAIN_AFTER_MINUTES,
    ML_RETRAIN_MIN_NEW_EVENTS,
    ML_RETRAIN_MIN_NEW_VERDICTS,
    ML_TARGET_FPR,
    ML_TRAIN_MIN_SAMPLES,
)
from backend.database.connection import SessionLocal
from backend.database.models import (
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    Verdict,
)

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

# Login types that are ordinary for interactive work; anything else is novel.
_COMMON_LOGON_TYPES = {2, 3, 10, 11}
_NIGHT_HOURS = {22, 23, 0, 1, 2, 3, 4, 5}

#: Remote IP prefixes treated as *attack* for the network supervised layer
#: (documentation/test ranges used by scripted attack ground truth; real
#: production deployments would extend this with threat-intel subnets).
_NET_ATTACK_PREFIXES = ("203.0.113.", "198.51.100.", "45.")

_DEFAULT_THRESHOLDS = {"login": 0.5, "process": 0.5, "network": 0.5}


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
    ``"192.168.99.77"``, ``"0xC000006A"``). This returns a deterministic
    numeric sketch so the feature vector is not a near-constant. Nonexistent
    values map to ``0.0``.
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
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()

    def _digits(s: str) -> float:
        return sum(int(c) for c in s if c.isdigit())

    if "." in text and all(ch.isdigit() for ch in text.replace(".", "")):
        try:
            parts = [int(p) for p in text.split(".") if p.isdigit()]
            if len(parts) == 4:
                return float((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3])
        except (TypeError, ValueError, OverflowError):
            pass
    if text.startswith("0x"):
        return float(_digits(text))
    if text.isdigit():
        return float(text)
    return float(_digits(text) or 0)


def _time_features(event) -> tuple[float, float, float]:
    """(hour_of_day, is_night, is_weekend) computed from the event timestamp.

    Unknown timestamps produce a neutral (0, 0, 0) vector so offline/dict
    paths keep a stable feature space.
    """
    ts = None
    try:
        ts = event.timestamp
    except AttributeError:
        pass
    if ts is None and isinstance(event, dict):
        ts = event.get("timestamp")
    if ts is None:
        return 0.0, 0.0, 0.0
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return 0.0, 0.0, 0.0
    try:
        hour = ts.hour
        return (
            round(hour / 24.0, 4),
            1.0 if hour in _NIGHT_HOURS else 0.0,
            1.0 if ts.weekday() >= 5 else 0.0,
        )
    except (TypeError, ValueError, AttributeError):
        return 0.0, 0.0, 0.0


def event_feature_vector(event) -> list[float] | None:
    """Feature vector for a single event (None if the behavior stream is unknown).

    v2 feature space (see ``ML_FEATURE_VERSION``): time-of-day context and
    script/command-line signal are added to the v1 numeric facts. Training and
    scoring share this exact function, so the feature space never drifts.
    """
    event_id = event.event_id if not isinstance(event, dict) else event.get("event_id", 0)
    behavior = _behavior_of(int(event_id))
    hour, is_night, is_weekend = _time_features(event)
    if behavior == "login":
        logon_type = _fact(event, "logon_type")
        return [
            int(event_id),
            logon_type,
            _ip_feature(event, "sub_status") / 100.0,
            _ip_feature(event, "source_ip") / 4_294_967_296.0,
            _bool_fact(event, "is_locked"),
            hour,
            is_night,
            is_weekend,
            1.0 if logon_type > 0 and int(logon_type) not in _COMMON_LOGON_TYPES else 0.0,
        ]
    if behavior == "process":
        return [
            int(event_id),
            _bool_fact(event, "has_encoded"),
            _bool_fact(event, "has_download"),
            _bool_fact(event, "has_hidden"),
            _bool_fact(event, "group_sid"),
            min(1.0, _fact(event, "script_len") / 256.0),
            min(1.0, _fact(event, "cmdline_len") / 512.0),
            hour,
            _bool_fact(event, "has_remote"),
        ]
    return None


# ---------------------------------------------------------------------------
# Feature extraction (per behavior stream)
# ---------------------------------------------------------------------------
def _verdict_map(session) -> dict[int, int]:
    """Authoritative analyst labels: {event_id: 1|0} from the feedback loop.

    Analyst-confirmed attacks (``true_positive``) are always labelled 1 and
    confirmed false-positives 0 - these override the heuristic labeler for
    supervised training so real analyst judgment shapes the decision surface.
    """
    rows = session.execute(select(Verdict.event_id, Verdict.verdict)).all()
    return {
        int(event_id): (1 if verdict == "true_positive" else 0)
        for event_id, verdict in rows
    }


def _load_behavior_features(
    session,
    since: datetime,
    event_ids: set[int],
    with_labels: bool = False,
    cutoff: datetime | None = None,
):
    """Per-event feature matrix for a behavior stream.

    ``with_labels=True`` also returns a binary label per row - analyst
    verdicts override the heuristic facts for events the analyst reviewed.
    ``cutoff`` caps the upper bound so baseline fitting never sees a window.
    """
    stmt = select(NormalizedEvent).where(
        NormalizedEvent.event_id.in_(event_ids),
        NormalizedEvent.timestamp >= since,
    )
    if cutoff is not None:
        stmt = stmt.where(NormalizedEvent.timestamp < cutoff)
    rows = session.scalars(stmt).all()
    X = []
    y = []
    verdicts = _verdict_map(session) if with_labels else {}
    for ev in rows:
        features = event_feature_vector(ev)
        if not features:
            continue
        X.append(features)
        if with_labels:
            if ev.id in verdicts:
                y.append(verdicts[ev.id])
                continue
            facts = ((ev.raw_json or {}).get("facts") or {}) if ev.raw_json else {}
            y.append(
                1 if MLAnomalyDetector._is_attack_sample(ev.event_id, facts) else 0
            )
    if with_labels:
        return (
            np.array(X, dtype=float) if X else np.empty((0, 9)),
            np.array(y, dtype=int) if y else np.empty((0,), dtype=int),
        )
    return np.array(X, dtype=float) if X else np.empty((0, 9))


def _load_network_features(
    session, since: datetime, cutoff: datetime | None = None
) -> tuple[np.ndarray, list[dict]]:
    """Per-remote-IP flow features: count, distinct ports, bytes, duration.

    Returns (X, rows) where ``rows`` carries the remote_ip label for each
    feature row so the IP encoder can be retained for scoring unseen hosts.
    """
    stmt = select(
        NetworkConnection.remote_ip,
        func.count(NetworkConnection.id),
        func.count(func.distinct(NetworkConnection.remote_port)),
        func.sum(NetworkConnection.bytes_sent),
        func.sum(NetworkConnection.bytes_recv),
        func.avg(NetworkConnection.duration_seconds),
    ).where(NetworkConnection.observed_at >= since)
    if cutoff is not None:
        stmt = stmt.where(NetworkConnection.observed_at < cutoff)
    rows = session.execute(stmt.group_by(NetworkConnection.remote_ip)).all()
    if not rows:
        return np.empty((0, 8)), []
    encoder = LabelEncoder()
    ips = [r[0] or "unknown" for r in rows]
    encoded = encoder.fit_transform(ips).reshape(-1, 1)
    flows = np.array(
        [
            [
                int(r[1]),
                int(r[2]),
                float(r[3] or 0) / 1_000_000.0,
                float(r[4] or 0) / 1_000_000.0,
                float(r[5] or 0) / 3600.0,
                (float(r[3] or 0) / 1_000_000.0) / max(float(r[5] or 0) / 3600.0, 0.01),
            ]
            for r in rows
        ],
        dtype=float,
    )
    X = np.hstack([encoded, flows])
    X = np.hstack([X, np.zeros((X.shape[0], 2))])  # is_novel, hour (filled at score time)
    return X, [{"remote_ip": ip} for ip in ips]


class MLAnomalyDetector:
    """Per-behavior Isolation Forest + calibrated supervised classifier."""

    def __init__(self, load_persisted: bool = False):
        self.models: dict[str, IsolationForest] = {}
        self.supervised = None
        self.supervised_name = "none"
        self.supervised_by_stream: dict[str, object] = {}
        self.supervised_name_by_stream: dict[str, str] = {}
        self.trained_at: str | None = None
        self.n_samples = 0
        self.events_at_train = 0
        self.encoders: dict[str, LabelEncoder] = {}
        self.thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
        self.baselines: dict[str, np.ndarray] = {}
        self._persisted = False
        self._load_meta()
        if load_persisted and not self.models:
            self._load_bundle()

    # ------------------------------------------------------------------
    # Persistence (models + metadata)
    # ------------------------------------------------------------------
    def _bundle_path(self) -> Path:
        return Path(ML_MODEL_BUNDLE)

    def _meta_path(self):
        return ML_META_FILE

    def _load_meta(self) -> None:
        """Restore the last training snapshot so staleness survives restarts."""
        try:
            path = self._meta_path()
            if not path or not os.path.exists(path):
                return
            with open(path, encoding="utf-8") as fh:
                meta = json.load(fh)
            self.trained_at = meta.get("trained_at")
            self.n_samples = int(meta.get("n_samples", 0))
            self.events_at_train = int(meta.get("events_at_train", 0))
            self.supervised_name = meta.get("supervised", "none")
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **{k: float(v) for k, v in (meta.get("thresholds") or {}).items()},
            }
        except (OSError, ValueError, TypeError):
            logger.warning("Could not read ML metadata at %s", ML_META_FILE)

    def _save_meta(self) -> None:
        try:
            path = self._meta_path()
            if not path:
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "trained_at": self.trained_at,
                        "n_samples": self.n_samples,
                        "events_at_train": self.events_at_train,
                        "supervised": self.supervised_name,
                        "thresholds": self.thresholds,
                        "feature_version": ML_FEATURE_VERSION,
                    },
                    fh,
                    indent=2,
                )
        except OSError:
            logger.warning("Could not persist ML metadata to %s", ML_META_FILE)

    def _save_bundle(self) -> None:
        """Persist the trained models so restarts do not cold-start."""
        if not self.models:
            return
        try:
            import joblib

            bundle = {
                "feature_version": ML_FEATURE_VERSION,
                "models": self.models,
                "encoders": self.encoders,
                "supervised": self.supervised,
                "supervised_name": self.supervised_name,
                "supervised_by_stream": self.supervised_by_stream,
                "supervised_name_by_stream": self.supervised_name_by_stream,
                "thresholds": self.thresholds,
                "baselines": {k: v.tolist() for k, v in self.baselines.items()},
            }
            path = self._bundle_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(bundle, path, compress=3)
            self._persisted = True
        except Exception:  # noqa: BLE001
            logger.warning("Could not persist ML model bundle", exc_info=True)

    def _load_bundle(self) -> bool:
        """Restore persisted models; ignored when the feature space changed."""
        path = self._bundle_path()
        if not path.exists():
            return False
        try:
            import joblib

            bundle = joblib.load(path)
            if bundle.get("feature_version") != ML_FEATURE_VERSION:
                logger.info("ML bundle has a different feature version; retraining")
                return False
            self.models = bundle.get("models", {})
            self.encoders = bundle.get("encoders", {})
            self.supervised = bundle.get("supervised")
            self.supervised_name = bundle.get("supervised_name", "none")
            self.supervised_by_stream = bundle.get("supervised_by_stream") or {}
            self.supervised_name_by_stream = bundle.get("supervised_name_by_stream") or {}
            self.thresholds = {
                **dict(_DEFAULT_THRESHOLDS),
                **bundle.get("thresholds", {}),
            }
            self.baselines = {
                k: np.asarray(v, dtype=float)
                for k, v in (bundle.get("baselines") or {}).items()
            }
            self._persisted = True
            return bool(self.models)
        except Exception:  # noqa: BLE001
            logger.warning("Could not load ML model bundle; retraining", exc_info=True)
            return False

    # ------------------------------------------------------------------
    def _events_since_train(self, session) -> int:
        if not self.trained_at:
            return 0
        try:
            since = datetime.fromisoformat(self.trained_at)
        except ValueError:
            return 0
        return int(
            session.scalar(
                select(func.count(NormalizedEvent.id)).where(NormalizedEvent.timestamp > since)
            ) or 0
        )

    def _drift_result(self, session=None) -> tuple[bool, str]:
        """Sustained-anomaly drift check over recently *scored* events.

        Returns ``(drifted, reason)``. When recent traffic keeps landing above
        the per-stream thresholds, the learned baseline no longer matches the
        live distribution - exactly the "attacker became the new normal"
        scenario. A drifted model is marked stale so the scheduler retrains
        and the operator sees the signal.
        """
        if not self.trained_at or not self.models:
            return False, "untrained"
        close = session is None
        session = session or SessionLocal()
        try:
            try:
                since = datetime.fromisoformat(self.trained_at)
            except ValueError:
                return False, "unparseable-trained-at"
            rows = session.execute(
                select(NormalizedEvent.event_id, NormalizedEvent.ml_score).where(
                    NormalizedEvent.timestamp >= since,
                    NormalizedEvent.ml_score.isnot(None),
                )
            ).all()
            flagged = 0
            total = 0
            for event_id, ml_score in rows:
                behavior = _behavior_of(int(event_id))
                threshold = self.thresholds.get(behavior, 0.5)
                total += 1
                if float(ml_score or 0.0) > threshold:
                    flagged += 1
            if total < ML_DRIFT_MIN_SAMPLES:
                return False, f"insufficient-recent-scores ({total}<{ML_DRIFT_MIN_SAMPLES})"
            rate = flagged / total
            if rate > ML_DRIFT_RATE:
                return True, (
                    f"drifted: {rate:.1%} of {total} recent events flagged "
                    f"(> {ML_DRIFT_RATE:.0%})"
                )
            return False, f"ok ({rate:.1%} flagged)"
        finally:
            if close:
                session.close()

    def is_stale(self, session=None) -> tuple[bool, str]:
        """True when the model should be retrained (age, volume, or drift)."""
        if not self.trained_at:
            return True, "never-trained"
        try:
            age = datetime.now(timezone.utc) - datetime.fromisoformat(self.trained_at)
        except ValueError:
            return True, "unparseable-trained-at"
        if age > timedelta(minutes=ML_RETRAIN_AFTER_MINUTES):
            return True, (
                f"trained {age.seconds // 60}m ago "
                f"(> {ML_RETRAIN_AFTER_MINUTES}m)"
            )
        if session is not None:
            new_events = self._events_since_train(session)
            if new_events >= ML_RETRAIN_MIN_NEW_EVENTS:
                return True, f"{new_events} new events since training (>= {ML_RETRAIN_MIN_NEW_EVENTS})"
            new_verdicts = int(
                session.scalar(
                    select(func.count(Verdict.id)).where(
                        Verdict.created_at > datetime.fromisoformat(self.trained_at)
                    )
                )
                or 0
            )
            if new_verdicts >= ML_RETRAIN_MIN_NEW_VERDICTS:
                return True, (
                    f"{new_verdicts} new analyst verdicts (>= {ML_RETRAIN_MIN_NEW_VERDICTS})"
                )
        drifted, drift_reason = self._drift_result(session)
        if drifted:
            return True, drift_reason
        return False, "fresh"

    # ------------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        return HAS_SKLEARN and bool(self.models)

    # ------------------------------------------------------------------
    @staticmethod
    def _compact_baseline(raws: np.ndarray, max_points: int = 1024) -> np.ndarray:
        """Sorted, de-duplicated copy of the training raw scores (monotone CDF)."""
        arr = np.sort(np.asarray(raws, dtype=float))
        unique = np.unique(arr)
        if len(unique) <= max_points:
            return unique
        idx = np.linspace(0, len(unique) - 1, max_points).astype(int)
        return unique[idx]

    @classmethod
    def _rank_of(cls, raws, baseline: np.ndarray | None) -> np.ndarray:
        """Position of raw scores within the training CDF, in [0, 1].

        A raw score sitting at the training median maps to ~0.5; one more
        extreme than 97% of the baseline maps to ~0.97. Falls back to the raw
        score when no CDF is available.
        """
        raws = np.atleast_1d(np.asarray(raws, dtype=float))
        if baseline is None or len(baseline) == 0:
            return np.clip(raws, 0.0, 1.0)
        if len(baseline) == 1:
            # A single-point baseline cannot discriminate anything - map every
            # score to the median rank instead of degenerating to 0 (which
            # would push the CFAR boundary to the 0.05 floor and flag all
            # traffic).
            return np.full_like(raws, 0.5)
        ranks = np.interp(raws, baseline, np.linspace(0.0, 1.0, len(baseline)))
        return np.clip(ranks, 0.0, 1.0)

    # ------------------------------------------------------------------
    # Threshold tuning
    # ------------------------------------------------------------------
    @staticmethod
    def _tune_threshold(model, X: np.ndarray, y, supervised=None, target_fpr: float = None):
        """Return ``(threshold, baseline_cdf)`` for a freshly-fit stream model.

        The threshold lives in the *deployed* score space - the rank of the
        IsolationForest raw score when no supervised classifier is active,
        otherwise the exact ``0.6*rank + 0.4*p`` blend used by
        :meth:`_combined_score`. Tuning on the deployed space keeps the
        decision boundary consistent with what actually runs:

        * **CFAR boundary (always)** - the ``(1 - target_fpr)`` quantile of
          the training score distribution, so at most ``target_fpr`` of the
          locally-learned baseline falls above it. Label-free, so a
          pure-benign history still flags tails.
        * **F1 grid (when labels exist)** - the boundary maximising F1 on the
          labelled split. The final boundary never sits *stricter* than the
          CFAR one (more sensitive of the two), which prevents recall
          collapse when labels are sparse or noisy.

        ``baseline_cdf`` is always the raw-score CDF (the input to
        :meth:`_rank_of`), so the stored baselines keep their semantics.
        """
        target_fpr = ML_TARGET_FPR if target_fpr is None else target_fpr
        if len(X) == 0:
            return 0.5, np.empty((0,))
        raws = np.array(
            [MLAnomalyDetector._score_with(model, row) for row in X], dtype=float
        )
        baseline = MLAnomalyDetector._compact_baseline(raws)
        ranks = MLAnomalyDetector._rank_of(raws, baseline)
        if supervised is not None:
            try:
                proba = supervised.predict_proba(X)
                p = proba[:, 1] if proba.shape[1] > 1 else np.zeros(len(X))
            except Exception:  # noqa: BLE001
                p = np.zeros(len(X))
            scores = 0.6 * ranks + 0.4 * p
        else:
            scores = ranks
        score_baseline = MLAnomalyDetector._compact_baseline(scores)
        if len(score_baseline):
            cfar = float(np.quantile(score_baseline, 1.0 - target_fpr))
        else:
            cfar = 0.5
        cfar = float(np.clip(cfar, 0.05, 0.98))
        if y is None or len(np.unique(y)) < 2:
            return cfar, baseline
        # The F1 grid may only lower the boundary while keeping the
        # labelled-benign false-alarm rate inside the same budget CFAR uses.
        # The boundary must stay at or above the benign floor, otherwise the
        # F1 optimum collapses to a degenerate near-zero threshold (recall
        # driven by FN symmetry, not real separation).
        y_arr = np.asarray(y)
        scores_arr = np.asarray(scores)
        benign = scores_arr[y_arr == 0]
        if len(benign) > 0:
            floor = float(np.quantile(benign, 1.0 - target_fpr))
        else:
            floor = 0.05
        floor = float(np.clip(floor, 0.05, 0.98))
        best_t, best_f1 = floor, -1.0
        for t in np.linspace(floor, 0.98, 47):
            pred = scores_arr > t
            tp = int(((pred) & (y_arr == 1)).sum())
            fp = int(((pred) & (y_arr == 0)).sum())
            fn = int(((~pred) & (y_arr == 1)).sum())
            if tp + fp + fn == 0:
                continue
            precision = tp / max(tp + fp, 1)
            recall = tp / max(tp + fn, 1)
            f1 = 2 * precision * recall / max(precision + recall, 1e-9)
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
        if best_f1 <= 0:
            return cfar, baseline
        return best_t, baseline

    # ------------------------------------------------------------------
    # Label helpers (shared between supervised training and validation)
    # ------------------------------------------------------------------
    @staticmethod
    def _is_attack_sample(event_id: int, facts: dict) -> bool:
        """Heuristic ground truth for the supervised layer.

        Labels are derived from the *feature-relevant* facts (the same
        signals the ML vectors encode) so attack samples genuinely occupy a
        different region of the feature space than benign baseline samples.
        """
        eid = int(event_id)
        src = str(facts.get("source_ip", "") or "")
        logon_type = int(facts.get("logon_type") or 0)
        external = src.startswith(("203.0.113.", "198.51.100.", "45."))
        scanner = src.startswith(("192.168.99", "10."))

        if eid == 4625:  # failed logon
            if scanner or external:
                return True
            if bool(facts.get("is_locked")):
                return True
            if logon_type > 0 and logon_type not in _COMMON_LOGON_TYPES:
                return True
            return False
        if eid == 4624:  # successful logon (interactive remote / scanner subnet)
            return (external or scanner) and logon_type == 10
        if eid in (4634, 4647, 4771):  # benign logon family
            return False
        if eid in (4104, 4103):  # PowerShell — encoded/download/hidden signal
            return bool(
                facts.get("has_encoded") or facts.get("has_download") or facts.get("has_hidden")
            )
        if eid == 4688:  # process creation — masquerading / long obfuscated argv
            image = str(facts.get("image_path", "") or facts.get("new_process", "") or "")
            path_like = "public" in image.lower() or "\\temp" in image.lower()
            try:
                long_argv = float(facts.get("cmdline_len") or 0) > 400
            except (TypeError, ValueError):
                long_argv = False
            return bool(facts.get("has_encoded")) or path_like or long_argv
        if eid in (4720, 4732, 7045, 4698):  # risky mutation
            return True
        return bool(facts.get("is_anomalous") or facts.get("attack"))

    @staticmethod
    def _labeled_network_samples(session, since: datetime) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Per-remote-IP flow features with attack labels for the network stream.

        Label source: remote IPs inside the known attack prefixes (scripted
        ground truth / threat-intel ranges). Returns (X, y, ips) aligned to
        the same feature space used at score time.
        """
        X, rows = _load_network_features(session, since)
        ips = [r["remote_ip"] for r in rows]
        if not ips:
            return X, np.empty((0,), dtype=int), []
        y = np.array(
            [1 if ip.startswith(_NET_ATTACK_PREFIXES) else 0 for ip in ips], dtype=int
        )
        return X, y, ips

    @staticmethod
    def _labeled_samples(session) -> dict[str, tuple[list[list[float]], list[list[float]]]]:
        """Per-stream labelled samples: attack vectors vs benign baseline.

        Builds labels from the *real* feature vectors (via
        :func:`event_feature_vector`) so the supervised classifiers are
        trained on the same space used for scoring.
        """
        out: dict[str, tuple[list[list[float]], list[list[float]]]] = {
            "login": ([], []),
            "process": ([], []),
            "network": ([], []),
        }
        rows = session.execute(
            select(NormalizedEvent.id, NormalizedEvent.raw_json, NormalizedEvent.event_id)
        ).all()
        verdicts = _verdict_map(session)
        for event_id, raw, eid in rows:
            facts = (raw or {}).get("facts", {})
            behavior = _behavior_of(int(eid))
            if behavior not in out:
                continue
            features = event_feature_vector({"event_id": eid, "raw_json": raw})
            if not features:
                continue
            if event_id in verdicts:
                is_attack = bool(verdicts[event_id])
            else:
                is_attack = MLAnomalyDetector._is_attack_sample(eid, facts)
            (out[behavior][0] if is_attack else out[behavior][1]).append(features)

        since = datetime.now(timezone.utc) - timedelta(hours=24)
        net_X, net_y, net_ips = MLAnomalyDetector._labeled_network_samples(session, since)
        for i, ip in enumerate(net_ips):
            (out["network"][0] if net_y[i] else out["network"][1]).append(net_X[i].tolist())
        return out

    def _validation_data(self, session, since: datetime) -> dict[str, tuple[np.ndarray, np.ndarray]]:
        """Windowed labelled validation set, grouped by behavior stream."""
        rows = session.execute(
            select(
                NormalizedEvent.id,
                NormalizedEvent.raw_json,
                NormalizedEvent.event_id,
                NormalizedEvent.timestamp,
            )
            .where(NormalizedEvent.timestamp >= since)
        ).all()
        out: dict[str, list] = {"login": [[], []], "process": [[], []], "network": [[], []]}
        verdicts = _verdict_map(session)
        for row_id, raw, event_id, timestamp in rows:
            facts = (raw or {}).get("facts", {})
            features = event_feature_vector(
                {"event_id": event_id, "raw_json": raw, "timestamp": timestamp}
            )
            if not features:
                continue
            behavior = _behavior_of(int(event_id))
            if row_id in verdicts:
                label = verdicts[row_id]
            else:
                label = 1 if MLAnomalyDetector._is_attack_sample(event_id, facts) else 0
            out[behavior][0].append(features)
            out[behavior][1].append(label)
        return {
            beh: (np.array(x, dtype=float), np.array(y, dtype=int))
            for beh, (x, y) in out.items()
            if len(x) >= 4 and len(set(y)) >= 2
        }

    # ------------------------------------------------------------------
    def train(
        self,
        session=None,
        hours: int = 24,
        validate: bool = False,
        persist: bool = True,
        cutoff: datetime | None = None,
    ) -> dict:
        """Train per-stream Isolation Forests + supervised classifier.

        ``validate=True`` gates replacement behind a labelled-window
        comparison against the currently loaded models (production path);
        tests and cold starts always train freely.

        ``persist=False`` trains in-memory only (evaluation harnesses) so a
        validation run can never overwrite the production bundle.

        ``cutoff`` (e.g. a campaign start) caps the training window so the
        baseline fit never sees the attack window.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        close = session is None
        session = session or SessionLocal()
        try:
            since = datetime.now(timezone.utc) - timedelta(hours=hours)

            login_X, login_y = _load_behavior_features(
                session, since, LOGIN_EVENTS, with_labels=True, cutoff=cutoff
            )
            process_X, process_y = _load_behavior_features(
                session, since, PROCESS_EVENTS, with_labels=True, cutoff=cutoff
            )
            network_X, network_rows = _load_network_features(session, since, cutoff=cutoff)
            network_y = np.empty((0,), dtype=int)
            if len(network_X):
                _, network_y, _ = self._labeled_network_samples(session, since)

            new_models: dict[str, IsolationForest] = {}
            new_thresholds: dict[str, float] = dict(_DEFAULT_THRESHOLDS)
            new_baselines: dict[str, np.ndarray] = {}
            stream_X: dict[str, np.ndarray] = {}
            stream_y: dict[str, np.ndarray] = {}
            for behavior, X, y in (
                ("login", login_X, login_y),
                ("process", process_X, process_y),
                ("network", network_X, network_y),
            ):
                if len(X) < 3:
                    continue
                model = IsolationForest(
                    contamination=ML_CONTAMINATION,
                    random_state=ML_RANDOM_STATE,
                    n_estimators=100,
                    max_samples=min(256, len(X)),
                )
                model.fit(X)
                new_models[behavior] = model
                stream_X[behavior] = X
                stream_y[behavior] = y

            if not new_models:
                return {"status": "insufficient-data", "trained": False}

            # Supervised layer: per-stream attack-vs-baseline classifiers. Streams
            # have their own feature spaces (login/process 9-dim, network
            # 9-dim), so each is trained on its own vector space. Network
            # buckets are aggregates, so even a handful of labelled attack IPs
            # carries signal (rate + novelty separate cleanly).
            new_supervised_by_stream: dict[str, object] = {}
            new_supervised_name_by_stream: dict[str, str] = {}
            new_supervised = None
            new_supervised_name = "none"
            for behavior, (atk, ben) in self._labeled_samples(session).items():
                min_attacks = 3 if behavior == "network" else 10
                if len(atk) < min_attacks or len(ben) < 3:
                    continue
                X_all = np.vstack([ben, atk])
                y_all = np.array([0] * len(ben) + [1] * len(atk))
                stream_model, stream_name = self._build_classifier(X_all, y_all)
                new_supervised_by_stream[behavior] = stream_model
                new_supervised_name_by_stream[behavior] = stream_name

            # Thresholds are tuned in the deployed score space (IF rank blended
            # with the supervised attack probability when available), so the
            # stored boundary matches what scoring actually compares against.
            for behavior in new_models:
                new_thresholds[behavior], new_baselines[behavior] = self._tune_threshold(
                    new_models[behavior],
                    stream_X[behavior],
                    stream_y.get(behavior),
                    supervised=new_supervised_by_stream.get(behavior),
                )
            # Singular fallback keeps legacy callers (score_event) working.
            if new_supervised_by_stream:
                best_stream = (
                    "login" if "login" in new_supervised_by_stream
                    else next(iter(new_supervised_by_stream))
                )
                new_supervised = new_supervised_by_stream[best_stream]
                new_supervised_name = new_supervised_name_by_stream[best_stream]

            n_samples = int(len(login_X) + len(process_X) + len(network_X))

            # Validation gate: only replace models that are not worse.
            if validate and self.models and self._gate_replacement(
                session, since, new_models
            ):
                logger.info("ML retrain: keeping existing models (no improvement)")
                return {
                    "status": "kept-existing",
                    "trained": True,
                    "samples": self.n_samples,
                    "streams": list(self.models.keys()),
                    "supervised": self.supervised_name,
                    "trained_at": self.trained_at,
                }

            self.models = new_models
            self.thresholds = new_thresholds
            self.baselines = new_baselines
            self.supervised = new_supervised
            self.supervised_name = new_supervised_name
            self.supervised_by_stream = new_supervised_by_stream
            self.supervised_name_by_stream = new_supervised_name_by_stream
            self.n_samples = n_samples
            self.encoders = {}
            if "network" in self.models and network_rows:
                encoder = LabelEncoder()
                encoder.fit([r["remote_ip"] for r in network_rows])
                self.encoders["network"] = encoder

            if self.n_samples < ML_TRAIN_MIN_SAMPLES:
                logger.info(
                    "Only %d samples; training anyway (min %d)", self.n_samples, ML_TRAIN_MIN_SAMPLES
                )

            self.trained_at = datetime.now(timezone.utc).isoformat()
            self.events_at_train = int(
                session.scalar(select(func.count(NormalizedEvent.id))) or 0
            )
            if persist:
                self._save_meta()
                self._save_bundle()
            logger.info(
                "ML models trained on %d samples; streams=%s supervised=%s thresholds=%s",
                self.n_samples, list(self.models.keys()), self.supervised_name,
                {k: round(v, 2) for k, v in self.thresholds.items()},
            )
            return {
                "status": "ok",
                "trained": True,
                "samples": self.n_samples,
                "streams": list(self.models.keys()),
                "supervised": self.supervised_name,
                "thresholds": self.thresholds,
                "trained_at": self.trained_at,
            }
        finally:
            if close:
                session.close()

    def _gate_replacement(self, session, since, new_models) -> bool:
        """True = keep the existing models (new ones did not beat them).

        Compares per-stream ROC-AUC on a labelled validation window; when no
        stream can be compared the retrain proceeds.
        """
        try:
            from sklearn.metrics import roc_auc_score
        except ImportError:
            return False
        deltas: list[float] = []
        for behavior, (X, y) in self._validation_data(session, since).items():
            old = self.models.get(behavior)
            new = new_models.get(behavior)
            if old is None or new is None or len(X) < 6:
                continue
            try:
                old_auc = roc_auc_score(y, old.decision_function(X))
                new_auc = roc_auc_score(y, new.decision_function(X))
            except ValueError:
                continue
            deltas.append(new_auc - old_auc)
        if not deltas:
            return False
        return sum(deltas) / len(deltas) < -0.02

    @staticmethod
    def _build_classifier(X, y):
        """XGBoost when available, else sklearn random forest, calibrated."""
        pos = int(y.sum())
        neg = int(len(y) - pos)
        scale = (neg / max(pos, 1)) if pos and neg else 1.0
        if HAS_XGBOOST:
            model = XGBClassifier(
                n_estimators=80, max_depth=3, learning_rate=0.1,
                random_state=ML_RANDOM_STATE, eval_metric="logloss",
                scale_pos_weight=scale, subsample=0.9, colsample_bytree=0.9,
            )
            model.fit(X, y)
            name = "xgboost"
        else:
            model = RandomForestClassifier(
                n_estimators=80, max_depth=5, random_state=ML_RANDOM_STATE,
                class_weight="balanced_subsample", min_samples_leaf=2,
            )
            model.fit(X, y)
            name = "random_forest"
        if len(y) >= 24 and min(pos, neg) >= 6:
            try:
                from sklearn.calibration import CalibratedClassifierCV

                cal = CalibratedClassifierCV(model, cv=3, method="isotonic")
                cal.fit(X, y)
                return cal, name + "+calibrated"
            except Exception:  # noqa: BLE001
                pass
        return model, name

    # ------------------------------------------------------------------
    def _combined_score(self, behavior: str, model, features: list[float]) -> float:
        """Blend the (rank-calibrated) IsolationForest anomaly signal with the
        supervised classifier's attack probability into a single [0,1] score."""
        raw = self._score_with(model, features)
        base = float(self._rank_of([raw], self.baselines.get(behavior))[0])
        classifier = self.supervised_by_stream.get(behavior) or self.supervised
        if classifier is None:
            return base
        p = self.supervised_proba(features, classifier)
        return float(max(0.0, min(1.0, 0.6 * base + 0.4 * p)))

    def score_event(self, features: list[float]) -> float:
        """Anomaly score in [0,1]; higher = more anomalous.

        Routes to the per-behavior model via the event_id carried in the
        first feature (login/process vectors both start with it), falling
        back to the login model for generic callers.
        """
        if not self.is_ready:
            return 0.0
        try:
            behavior = _behavior_of(int(features[0]))
        except (TypeError, ValueError, IndexError):
            behavior = "login"
        if behavior not in self.models:
            behavior = "login" if "login" in self.models else next(iter(self.models))
        model = self.models.get(behavior)
        return self._combined_score(behavior, model, features)

    def score_event_for_behavior(self, behavior: str, features: list[float]) -> float:
        model = self.models.get(behavior)
        if model is None:
            return 0.0
        return self._combined_score(behavior, model, features)

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

        Feature vector: [ip_code, count, distinct_ports, bytes_sent(MB),
        bytes_recv(MB), duration(h), send_rate(MB/s), is_novel, hour].
        """
        model = self.models.get("network")
        encoder = self.encoders.get("network")
        if model is None or encoder is None:
            return 0.0
        if remote_ip in encoder.classes_:
            code = float(encoder.transform([remote_ip])[0])
            novel = 0.0
        else:
            code = -1.0  # unseen host -> treat as novel
            novel = 1.0
        sent_mb = float(bytes_sent) / 1_000_000.0
        hours_dur = float(duration) / 3600.0
        rate = sent_mb / max(hours_dur, 0.01)
        return self._combined_score(
            "network",
            model,
            [
                code, float(count), float(distinct_ports),
                sent_mb, float(bytes_recv) / 1_000_000.0,
                hours_dur, rate, novel, 0.0,
            ],
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
                    score = self._combined_score(behavior, model, features)
                except Exception:  # noqa: BLE001
                    continue
                ev.ml_score = round(score, 4)
                scored += 1
                if score > self.thresholds.get(behavior, 0.5):
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
                    if score > self.thresholds.get("network", 0.5):
                        flagged += 1

            session.commit()
            return {"status": "ok", "scored": scored, "flagged": flagged}
        finally:
            if close:
                session.close()

    # ------------------------------------------------------------------
    def supervised_proba(self, features: list[float], classifier=None) -> float:
        """P(attack) from the supervised classifier, or 0.0 when untrained."""
        classifier = classifier or self.supervised
        if classifier is None:
            return 0.0
        arr = np.array([features], dtype=float)
        if arr.shape[1] != classifier.n_features_in_:
            return 0.0
        try:
            proba = classifier.predict_proba(arr)[0]
        except Exception:  # noqa: BLE001
            return 0.0
        return float(proba[1] if len(proba) > 1 else 0.0)

    def status(self, session=None) -> dict:
        drifted, drift_reason = self._drift_result(session)
        stale, reason = self.is_stale(session)
        return {
            "has_sklearn": HAS_SKLEARN,
            "has_xgboost": HAS_XGBOOST,
            "ready": self.is_ready,
            "trained_at": self.trained_at,
            "samples": self.n_samples,
            "events_at_train": self.events_at_train,
            "streams": list(self.models.keys()),
            "supervised": self.supervised_name,
            "supervised_streams": dict(self.supervised_name_by_stream),
            "thresholds": {k: round(v, 3) for k, v in self.thresholds.items()},
            "feature_version": ML_FEATURE_VERSION,
            "persisted": self._persisted,
            "stale": stale,
            "staleness_reason": reason,
            "drift": drifted,
            "drift_reason": drift_reason,
        }


_detector: MLAnomalyDetector | None = None


def get_detector() -> MLAnomalyDetector:
    global _detector
    if _detector is None:
        _detector = MLAnomalyDetector(load_persisted=True)
    return _detector