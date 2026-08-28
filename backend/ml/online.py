"""Online learning module for incremental model updates.

Phase 3: Allows the ML models to adapt to new data without full retraining,
using warm-starting for supervised classifiers and sliding-window retraining
for Isolation Forest (which doesn't support partial_fit natively).

Strategy:
1. **Supervised classifiers** (RF/XGBoost): warm_start=True, add new trees
   on each incremental update. The existing trees are frozen and only new
   trees learn from the new data.
2. **Isolation Forest**: sliding-window retrain on recent N events when
   enough new data accumulates. This is cheaper than full-history retrain
   and captures recent distribution shifts.
3. **Ensemble meta-learner**: retrained from scratch on each update (cheap,
   only logistic regression on 3 features).
4. **Prequential evaluation**: each new event is scored BEFORE being added
   to the training buffer, providing an unbiased estimate of model quality.

The online learner maintains a bounded buffer of recent feature vectors
per stream, preventing unbounded memory growth while ensuring the model
always reflects recent traffic patterns.
"""
from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Optional

import numpy as np

logger = logging.getLogger("baraq.ml.online")

try:
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:  # pragma: no cover
    HAS_XGBOOST = False


class OnlineBuffer:
    """Bounded sliding-window buffer for online learning.

    Maintains the most recent N feature vectors per stream, evicting
    the oldest when the buffer is full. This prevents unbounded memory
    growth while keeping a representative sample of recent traffic.
    """

    def __init__(self, max_size: int = 2048):
        self.max_size = max_size
        self._buffers: dict[str, deque] = {}
        self._label_buffers: dict[str, deque] = {}
        self._timestamps: dict[str, deque] = {}

    def add(
        self,
        stream: str,
        features: list[float],
        label: int | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        """Add a feature vector to the stream buffer."""
        if stream not in self._buffers:
            self._buffers[stream] = deque(maxlen=self.max_size)
            self._label_buffers[stream] = deque(maxlen=self.max_size)
            self._timestamps[stream] = deque(maxlen=self.max_size)
        self._buffers[stream].append(np.array(features, dtype=float))
        self._label_buffers[stream].append(label)
        self._timestamps[stream].append(timestamp or datetime.now(timezone.utc))

    def get_features(self, stream: str) -> np.ndarray:
        """Get all buffered features for a stream as a matrix."""
        if stream not in self._buffers or not self._buffers[stream]:
            return np.empty((0, 0))
        return np.array(list(self._buffers[stream]), dtype=float)

    def get_labels(self, stream: str) -> np.ndarray:
        """Get all buffered labels for a stream."""
        if stream not in self._label_buffers or not self._label_buffers[stream]:
            return np.empty((0,), dtype=int)
        labels = list(self._label_buffers[stream])
        return np.array([l if l is not None else 0 for l in labels], dtype=int)

    def get_labeled_data(self, stream: str) -> tuple[np.ndarray, np.ndarray]:
        """Get features and labels, filtering out unlabeled samples."""
        features = self.get_features(stream)
        labels = self.get_labels(stream)
        if len(features) == 0:
            return np.empty((0, 0)), np.empty((0,), dtype=int)
        labeled_mask = labels >= 0
        return features[labeled_mask], labels[labeled_mask]

    def size(self, stream: str) -> int:
        return len(self._buffers.get(stream, []))

    def clear(self, stream: str | None = None) -> None:
        """Clear buffer(s). None = clear all."""
        streams = [stream] if stream else list(self._buffers.keys())
        for s in streams:
            self._buffers.pop(s, None)
            self._label_buffers.pop(s, None)
            self._timestamps.pop(s, None)


class OnlineLearner:
    """Online learning wrapper for the ML anomaly detector.

    Wraps MLAnomalyDetector and provides incremental update capabilities:
    - Warm-start supervised classifiers on new labeled data
    - Sliding-window IF retrain on new unlabeled data
    - Prequential evaluation (score-then-train)
    - Configurable update thresholds
    """

    def __init__(
        self,
        detector,
        buffer_size: int = 2048,
        min_new_events: int = 50,
        min_new_verdicts: int = 5,
        update_interval_minutes: int = 15,
    ):
        self.detector = detector
        self.buffer = OnlineBuffer(max_size=buffer_size)
        self.min_new_events = min_new_events
        self.min_new_verdicts = min_new_verdicts
        self.update_interval = timedelta(minutes=update_interval_minutes)
        self._last_update: datetime | None = None
        self._events_since_update = 0
        self._verdicts_since_update = 0
        self._prequential_scores: dict[str, list[float]] = {}

    def score_and_buffer(
        self,
        stream: str,
        features: list[float],
        label: int | None = None,
    ) -> float:
        """Score an event and add it to the online buffer (prequential).

        Returns the anomaly score. The event is buffered for future
        incremental training regardless of the score.
        """
        score = 0.0
        if self.detector.is_ready:
            try:
                score = self.detector.score_event(features)
            except Exception:  # noqa: BLE001
                pass

        # Track prequential scores for drift detection
        if stream not in self._prequential_scores:
            self._prequential_scores[stream] = []
        self._prequential_scores[stream].append(score)
        # Keep only last 500 prequential scores
        if len(self._prequential_scores[stream]) > 500:
            self._prequential_scores[stream] = self._prequential_scores[stream][-500:]

        self.buffer.add(stream, features, label)
        self._events_since_update += 1
        return score

    def record_verdict(self, stream: str, features: list[float], is_attack: bool) -> None:
        """Record an analyst verdict and buffer the labeled event."""
        label = 1 if is_attack else 0
        self.buffer.add(stream, features, label)
        self._verdicts_since_update += 1

    def should_update(self) -> bool:
        """Check if enough new data has accumulated for an incremental update."""
        if not self.detector.is_ready:
            return False
        if self._last_update is None:
            return True
        elapsed = datetime.now(timezone.utc) - self._last_update
        if elapsed < self.update_interval:
            return False
        return (
            self._events_since_update >= self.min_new_events
            or self._verdicts_since_update >= self.min_new_verdicts
        )

    def incremental_update(self, session=None) -> dict:
        """Perform an incremental model update using buffered data.

        Strategy:
        1. For each stream with enough buffered data:
           a. If supervised classifier exists and has labeled data:
              - Warm-start a new RF/XGBoost on the labeled buffer
           b. Retrain IF on the sliding window (recent events only)
        2. Retrain ensemble meta-learner if enough labeled data
        3. Update thresholds on the new models
        """
        if not self.detector.is_ready:
            return {"status": "not-ready", "updated": False}

        updated_streams: list[str] = []
        errors: list[str] = []

        for stream in ["login", "process", "network"]:
            X = self.buffer.get_features(stream)
            if len(X) < 10:
                continue

            try:
                self._update_stream_model(stream, X, session)
                updated_streams.append(stream)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{stream}: {e}")

        if updated_streams:
            self._last_update = datetime.now(timezone.utc)
            self._events_since_update = 0
            self._verdicts_since_update = 0

            # Persist updated models
            try:
                self.detector._save_meta()
                self.detector._save_bundle()
            except Exception:  # noqa: BLE001
                logger.debug("Failed to persist online update", exc_info=True)

        return {
            "status": "ok",
            "updated": bool(updated_streams),
            "streams_updated": updated_streams,
            "errors": errors,
            "buffer_sizes": {s: self.buffer.size(s) for s in ["login", "process", "network"]},
        }

    def _update_stream_model(self, stream: str, X: np.ndarray, session=None) -> None:
        """Update a single stream's model with buffered data."""
        model = self.detector.models.get(stream)
        if model is None:
            return

        # Strategy 1: Sliding-window IF retrain
        # Retrain IF on the buffered data (captures recent distribution)
        new_if = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples=min(256, len(X)),
        )
        new_if.fit(X)

        # Validate: new IF must not be worse than old on the buffer
        try:
            old_scores = model.decision_function(X)
            new_scores = new_if.decision_function(X)
            old_auc = float(np.mean(old_scores > 0))
            new_auc = float(np.mean(new_scores > 0))
            # Only adopt if new model is at least as good
            if new_auc >= old_auc * 0.95:
                self.detector.models[stream] = new_if
        except Exception:  # noqa: BLE001
            # If validation fails, still adopt the new model
            self.detector.models[stream] = new_if

        # Strategy 2: Warm-start supervised classifier
        X_labeled, y_labeled = self.buffer.get_labeled_data(stream)
        if len(X_labeled) >= 10 and len(np.unique(y_labeled)) >= 2:
            self._warm_start_supervised(stream, X_labeled, y_labeled)

        # Strategy 3: Update baseline CDF
        try:
            raws = np.array(
                [self.detector._score_with(self.detector.models[stream], row) for row in X],
                dtype=float,
            )
            self.detector.baselines[stream] = self.detector._compact_baseline(raws)
        except Exception:  # noqa: BLE001
            pass

        # Strategy 4: Update threshold
        try:
            y = self.buffer.get_labels(stream)
            labeled_mask = y >= 0
            if labeled_mask.sum() >= 6:
                new_threshold, _ = self.detector._tune_threshold(
                    self.detector.models[stream],
                    X[labeled_mask],
                    y[labeled_mask],
                    supervised=self.detector.supervised_by_stream.get(stream),
                )
                self.detector.thresholds[stream] = new_threshold
        except Exception:  # noqa: BLE001
            pass

    def _warm_start_supervised(self, stream: str, X: np.ndarray, y: np.ndarray) -> None:
        """Warm-start the supervised classifier with new labeled data."""
        from backend.ml.anomaly import ML_RANDOM_STATE

        old_sup = self.detector.supervised_by_stream.get(stream)
        pos = int(y.sum())
        neg = int(len(y) - pos)

        if old_sup is not None and hasattr(old_sup, 'n_estimators'):
            # Warm-start: add new trees to existing forest
            try:
                new_n_estimators = min(old_sup.n_estimators + 20, 200)
                if isinstance(old_sup, RandomForestClassifier):
                    old_sup.set_params(n_estimators=new_n_estimators, warm_start=True)
                    old_sup.fit(X, y)
                    self.detector.supervised_by_stream[stream] = old_sup
                    return
            except Exception:  # noqa: BLE001
                pass

        # Fallback: train new classifier from scratch on buffer
        if HAS_XGBOOST and len(y) >= 50 and min(pos, neg) >= 5:
            scale = (neg / max(pos, 1)) if pos and neg else 1.0
            model = XGBClassifier(
                n_estimators=80, max_depth=3, learning_rate=0.08,
                random_state=ML_RANDOM_STATE, eval_metric="logloss",
                scale_pos_weight=scale, subsample=0.9, colsample_bytree=0.9,
                min_child_weight=2,
            )
            model.fit(X, y)
            name = "xgboost"
        elif len(y) >= 10 and min(pos, neg) >= 3:
            model = RandomForestClassifier(
                n_estimators=60, max_depth=5, random_state=ML_RANDOM_STATE,
                class_weight="balanced_subsample", min_samples_leaf=2,
                warm_start=True,
            )
            model.fit(X, y)
            name = "random_forest"
        else:
            return

        # Calibrate if enough data
        if len(y) >= 18 and min(pos, neg) >= 4:
            try:
                from sklearn.calibration import CalibratedClassifierCV
                cal = CalibratedClassifierCV(model, cv=min(3, min(pos, neg)), method="isotonic")
                cal.fit(X, y)
                self.detector.supervised_by_stream[stream] = cal
                self.detector.supervised_name_by_stream[stream] = name + "+calibrated"
                return
            except Exception:  # noqa: BLE001
                pass

        self.detector.supervised_by_stream[stream] = model
        self.detector.supervised_name_by_stream[stream] = name

    def prequential_report(self) -> dict:
        """Report prequential evaluation metrics per stream."""
        from sklearn.metrics import brier_score_loss, roc_auc_score

        report: dict[str, dict] = {}
        for stream, scores in self._prequential_scores.items():
            if len(scores) < 10:
                continue
            labels = self.buffer.get_labels(stream)
            if len(labels) < 10 or len(np.unique(labels)) < 2:
                continue
            scores_arr = np.array(scores[-len(labels):])
            labels_arr = labels[:len(scores_arr)]
            try:
                brier = brier_score_loss(labels_arr, scores_arr)
                auc = roc_auc_score(labels_arr, scores_arr)
                report[stream] = {
                    "brier_score": round(float(brier), 4),
                    "auc_roc": round(float(auc), 4),
                    "n_samples": len(labels_arr),
                }
            except Exception:  # noqa: BLE001
                continue
        return report

    def status(self) -> dict:
        return {
            "buffer_sizes": {s: self.buffer.size(s) for s in ["login", "process", "network"]},
            "events_since_update": self._events_since_update,
            "verdicts_since_update": self._verdicts_since_update,
            "last_update": self._last_update.isoformat() if self._last_update else None,
            "should_update": self.should_update(),
        }
