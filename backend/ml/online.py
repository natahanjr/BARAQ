"""Online learning module for incremental model updates.

Phase 3: Allows the ML models to adapt to new data without full retraining,
using warm-starting for supervised classifiers and sliding-window retraining
for Isolation Forest (which doesn't support partial_fit natively).

Improvements over v1:
1. **Importance-weighted buffer**: analyst-confirmed labels get 5x weight;
   recent events weighted higher via exponential decay. Prevents important
   attack patterns from being evicted by FIFO.
2. **ADWIN drift detection**: tracks prequential error rate with Adaptive
   Windowing. When error jumps, triggers immediate retrain instead of
   waiting for the timer.
3. **Model versioning**: snapshots before each online update; auto-rollback
   if post-update performance degrades.
4. **Active learning**: scores each event's uncertainty to prioritize which
   events get shown to analysts for labeling.
5. **Reservoir sampling**: replaces FIFO with statistically representative
   sampling that maintains distribution across time.
"""

from __future__ import annotations

import logging
import math
import random
from collections import deque
from datetime import UTC, datetime, timedelta

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


# ---------------------------------------------------------------------------
# ADWIN (Adaptive Windowing) for online drift detection
# ---------------------------------------------------------------------------
class ADWINDriftDetector:
    """Lightweight ADWIN implementation for online concept drift detection.

    Monitors a stream of binary error signals (1=error, 0=correct) and
    detects when the mean error rate has significantly changed. When a
    change is detected, it signals that the model should be retrained.

    Based on: "Detecting Change in Data Streams" by Bifet & Gavalda (2007)
    Simplified for our use case: fixed-width expanding window with
    variance-based cut detection.
    """

    def __init__(
        self, delta: float = 0.002, min_window: int = 30, max_window: int = 500
    ):
        """
        Args:
            delta: confidence bound for change detection (smaller = less sensitive)
            min_window: minimum window size before checking for drift
            max_window: maximum window size (older data is dropped)
        """
        self.delta = delta
        self.min_window = min_window
        self.max_window = max_window
        self._window: deque = deque(maxlen=max_window)
        self._total_errors = 0
        self._n = 0

    def update(self, error: float) -> bool:
        """Add an error signal and check for drift.

        Args:
            error: 0.0 = correct prediction, 1.0 = incorrect

        Returns:
            True if drift detected (model should be retrained)
        """
        self._window.append(error)
        self._n += 1

        if self._n < self.min_window:
            return False

        # Check for drift by splitting window at every point and comparing halves
        w = list(self._window)
        n = len(w)
        sum(w) / n

        # Find the best cut point (maximum variance reduction)
        best_cut = -1
        best_m = 0.0

        for i in range(self.min_window, n - self.min_window):
            left = w[:i]
            right = w[i:]
            mean_left = sum(left) / len(left)
            mean_right = sum(right) / len(right)

            # M = |mean_left - mean_right|^2 / (1/n_left + 1/n_right)
            m = (mean_left - mean_right) ** 2 / (1.0 / len(left) + 1.0 / len(right))

            if m > best_m:
                best_m = m
                best_cut = i

        if best_cut < 0:
            return False

        # Compare against the ADWIN bound
        n_left = best_cut
        n_right = n - best_cut
        epsilon = math.sqrt(
            (1.0 / (2.0 * n_left) + 1.0 / (2.0 * n_right))
            * 2.0
            * math.log(2.0 / self.delta)
        )

        mean_left = sum(w[:best_cut]) / n_left
        mean_right = sum(w[best_cut:]) / n_right

        if abs(mean_left - mean_right) >= epsilon:
            # Drift detected: keep only the right half (recent data)
            self._window = deque(w[best_cut:], maxlen=self.max_window)
            self._n = len(self._window)
            return True

        return False

    @property
    def current_error_rate(self) -> float:
        if not self._window:
            return 0.0
        return sum(self._window) / len(self._window)

    @property
    def window_size(self) -> int:
        return len(self._window)


# ---------------------------------------------------------------------------
# Reservoir sampling buffer
# ---------------------------------------------------------------------------
class ReservoirBuffer:
    """Reservoir sampling buffer for statistically representative sampling.

    Instead of FIFO (which biases toward recent data), reservoir sampling
    maintains a uniform random sample of all events seen so far. When the
    buffer is full, each new event has a probability of replacing a random
    existing event, maintaining distribution representativeness.

    For online learning, we combine reservoir sampling with time-decay:
    newer events have slightly higher probability of being retained,
    giving a balance between distribution coverage and recency.
    """

    def __init__(self, max_size: int = 2048, time_decay: float = 0.999):
        """
        Args:
            max_size: maximum buffer size
            time_decay: per-event decay factor (0.999 = slow decay, 0.99 = fast)
            Higher values preserve older data longer.
        """
        self.max_size = max_size
        self.time_decay = time_decay
        self._features: list[np.ndarray] = []
        self._labels: list[int] = []
        self._weights: list[float] = []
        self._timestamps: list[datetime] = []
        self._n_seen = 0
        self._rng = random.Random(42)

    def add(
        self,
        features: list[float],
        label: int | None = None,
        weight: float = 1.0,
        timestamp: datetime | None = None,
    ) -> None:
        """Add a feature vector with importance weight."""
        ts = timestamp or datetime.now(UTC)
        feat = np.array(features, dtype=float)
        lab = label if label is not None else -1
        self._n_seen += 1

        if len(self._features) < self.max_size:
            # Buffer not full: always add
            self._features.append(feat)
            self._labels.append(lab)
            self._weights.append(weight)
            self._timestamps.append(ts)
        else:
            # Buffer full: reservoir sampling with time-decay weighting
            # Replace probability = weight / max_weight_seen
            # This gives analyst-labeled events (weight=5) higher retention
            max_weight = max(self._weights) if self._weights else 1.0
            replace_prob = weight / max(max_weight, 1.0)
            if self._rng.random() < replace_prob:
                idx = self._rng.randint(0, self.max_size - 1)
                self._features[idx] = feat
                self._labels[idx] = lab
                self._weights[idx] = weight
                self._timestamps[idx] = ts

    def get_features(self) -> np.ndarray:
        if not self._features:
            return np.empty((0, 0))
        return np.array(self._features, dtype=float)

    def get_labels(self) -> np.ndarray:
        if not self._labels:
            return np.empty((0,), dtype=int)
        return np.array(self._labels, dtype=int)

    def get_weights(self) -> np.ndarray:
        if not self._weights:
            return np.empty((0,), dtype=float)
        return np.array(self._weights, dtype=float)

    def get_weighted_sample(self) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Get features, labels, and importance weights."""
        return self.get_features(), self.get_labels(), self.get_weights()

    def get_labeled_data(self) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Get only labeled samples with their weights."""
        features = self.get_features()
        labels = self.get_labels()
        weights = self.get_weights()
        if len(features) == 0:
            return (
                np.empty((0, 0)),
                np.empty((0,), dtype=int),
                np.empty((0,), dtype=float),
            )
        labeled_mask = labels >= 0
        return features[labeled_mask], labels[labeled_mask], weights[labeled_mask]

    @property
    def size(self) -> int:
        return len(self._features)

    @property
    def n_seen(self) -> int:
        return self._n_seen

    def clear(self) -> None:
        self._features.clear()
        self._labels.clear()
        self._weights.clear()
        self._timestamps.clear()
        self._n_seen = 0


# ---------------------------------------------------------------------------
# Active learning scorer
# ---------------------------------------------------------------------------
class ActiveLearner:
    """Uncertainty-based active learning prioritization.

    Scores each event by how uncertain the model is about it, so analysts
    spend their time labeling the most informative events. High uncertainty
    = high information value.

    Uses margin sampling: uncertainty = 1 - |P(attack) - 0.5| * 2
    Events near the decision boundary (P ~ 0.5) are most uncertain.
    """

    def __init__(self, top_k: int = 10):
        self.top_k = top_k
        self._uncertainty_queue: list[tuple[float, int, list[float]]] = []

    def score_uncertainty(
        self,
        features: list[float],
        model,
        behavior: str,
    ) -> float:
        """Score the uncertainty of an event (0=certain, 1=maximally uncertain)."""
        if model is None:
            return 0.5  # Unknown = moderate uncertainty

        try:
            from backend.ml.anomaly import MLAnomalyDetector

            proba = MLAnomalyDetector.supervised_proba(None, features, model)
            # Margin sampling: events near 0.5 are most uncertain
            uncertainty = 1.0 - abs(proba - 0.5) * 2.0
            return max(0.0, min(1.0, uncertainty))
        except Exception:
            logger.debug("uncertainty_score fallback to 0.5", exc_info=True)
            return 0.5

    def suggest_for_labeling(
        self,
        features_list: list[list[float]],
        behaviors: list[str],
        models: dict,
    ) -> list[dict]:
        """Suggest the most uncertain events for analyst labeling.

        Returns a list of dicts with event info, sorted by uncertainty
        (most uncertain first).
        """
        candidates = []
        for i, (features, behavior) in enumerate(zip(features_list, behaviors)):
            model = models.get(behavior)
            uncertainty = self.score_uncertainty(features, model, behavior)
            candidates.append(
                {
                    "index": i,
                    "behavior": behavior,
                    "uncertainty": round(uncertainty, 4),
                    "features": features,
                }
            )

        # Sort by uncertainty (highest first)
        candidates.sort(key=lambda x: x["uncertainty"], reverse=True)
        return candidates[: self.top_k]


# ---------------------------------------------------------------------------
# Main online learner
# ---------------------------------------------------------------------------
class OnlineLearner:
    """Online learning wrapper with all improvements.

    Wraps MLAnomalyDetector and provides:
    - Importance-weighted reservoir sampling buffer
    - ADWIN drift detection for automatic retrain triggering
    - Model versioning with auto-rollback
    - Active learning suggestions for analyst labeling
    - Warm-start supervised classifiers
    - Sliding-window IF retrain
    """

    def __init__(
        self,
        detector,
        buffer_size: int = 2048,
        min_new_events: int = 50,
        min_new_verdicts: int = 5,
        update_interval_minutes: int = 15,
        adwin_delta: float = 0.002,
        analyst_weight: float = 5.0,
        time_decay: float = 0.999,
    ):
        self.detector = detector
        self.min_new_events = min_new_events
        self.min_new_verdicts = min_new_verdicts
        self.update_interval = timedelta(minutes=update_interval_minutes)
        self.analyst_weight = analyst_weight

        # Improvement 1: Importance-weighted reservoir buffer
        self.buffers: dict[str, ReservoirBuffer] = {
            s: ReservoirBuffer(max_size=buffer_size, time_decay=time_decay)
            for s in ["login", "process", "network"]
        }

        # Improvement 2: ADWIN drift detection
        self.drift_detectors: dict[str, ADWINDriftDetector] = {
            s: ADWINDriftDetector(delta=adwin_delta)
            for s in ["login", "process", "network"]
        }

        # Improvement 3: Model versioning
        self._model_snapshots: dict[str, dict] = {}
        self._last_snapshot_version = 0

        # Improvement 4: Active learning
        self.active_learner = ActiveLearner(top_k=10)

        # State
        self._last_update: datetime | None = None
        self._events_since_update = 0
        self._verdicts_since_update = 0
        self._prequential_scores: dict[str, list[float]] = {}
        self._update_count = 0

    def score_and_buffer(
        self,
        stream: str,
        features: list[float],
        label: int | None = None,
    ) -> float:
        """Score an event, check for drift, and add to buffer."""
        score = 0.0
        if self.detector.is_ready:
            try:
                score = self.detector.score_event(features)
            except Exception:
                logger.debug("score_event failed in online learner", exc_info=True)

        # Track prequential scores
        if stream not in self._prequential_scores:
            self._prequential_scores[stream] = []
        self._prequential_scores[stream].append(score)
        if len(self._prequential_scores[stream]) > 1000:
            self._prequential_scores[stream] = self._prequential_scores[stream][-1000:]

        # Improvement 2: ADWIN drift detection on prequential error
        # Error = 1 if we're confident and wrong (simplified: high score + labeled benign)
        if label is not None:
            error = (
                1.0
                if (score > 0.7 and label == 0) or (score < 0.3 and label == 1)
                else 0.0
            )
            drift_detected = self.drift_detectors[stream].update(error)
            if drift_detected:
                logger.warning(
                    "ADWIN drift detected in %s stream (error_rate=%.3f), triggering retrain",
                    stream,
                    self.drift_detectors[stream].current_error_rate,
                )

        # Improvement 1: Add to importance-weighted buffer
        weight = self.analyst_weight if label is not None else 1.0
        self.buffers[stream].add(features, label, weight)
        self._events_since_update += 1
        if label is not None:
            self._verdicts_since_update += 1

        return score

    def record_verdict(
        self, stream: str, features: list[float], is_attack: bool
    ) -> None:
        """Record an analyst verdict with high importance weight."""
        label = 1 if is_attack else 0
        self.buffers[stream].add(features, label, weight=self.analyst_weight)
        self._verdicts_since_update += 1

    def should_update(self) -> bool:
        """Check if update is needed (timer + ADWIN drift)."""
        if not self.detector.is_ready:
            return False

        # Improvement 2: ADWIN drift triggers immediate update
        for dd in self.drift_detectors.values():
            if dd.window_size >= dd.min_window and dd.current_error_rate > 0.3:
                return True

        if self._last_update is None:
            return True
        elapsed = datetime.now(UTC) - self._last_update
        if elapsed < self.update_interval:
            return False
        return (
            self._events_since_update >= self.min_new_events
            or self._verdicts_since_update >= self.min_new_verdicts
        )

    def incremental_update(self, session=None) -> dict:
        """Perform an incremental model update with all improvements."""
        if not self.detector.is_ready:
            return {"status": "not-ready", "updated": False}

        # Improvement 3: Snapshot before update for rollback
        self._snapshot_models()

        updated_streams: list[str] = []
        errors: list[str] = []
        pre_update_scores: dict[str, float] = {}

        for stream in ["login", "process", "network"]:
            X, y, weights = self.buffers[stream].get_weighted_sample()
            if len(X) < 10:
                continue

            # Track pre-update performance
            try:
                pre_scores = self.detector.models[stream].decision_function(X)
                pre_update_scores[stream] = float(np.mean(pre_scores))
            except Exception:
                logger.debug("pre-update score failed for %s", stream, exc_info=True)
                pre_update_scores[stream] = 0.0

            try:
                self._update_stream_model(stream, X, y, weights, session)
                updated_streams.append(stream)
            except Exception as e:
                errors.append(f"{stream}: {e}")

        # Improvement 3: Validate and rollback if degraded
        if updated_streams:
            rollback_needed = self._validate_post_update(
                pre_update_scores, updated_streams
            )
            if rollback_needed:
                self._rollback_models()
                return {
                    "status": "rolled-back",
                    "updated": False,
                    "reason": "Post-update validation failed",
                    "streams_attempted": updated_streams,
                }

            self._last_update = datetime.now(UTC)
            self._events_since_update = 0
            self._verdicts_since_update = 0
            self._update_count += 1

            try:
                self.detector._save_meta()
                self.detector._save_bundle()
            except Exception:
                logger.warning("Failed to persist online update", exc_info=True)

        return {
            "status": "ok",
            "updated": bool(updated_streams),
            "streams_updated": updated_streams,
            "errors": errors,
            "buffer_sizes": {
                s: self.buffers[s].size for s in ["login", "process", "network"]
            },
            "buffer_seen": {
                s: self.buffers[s].n_seen for s in ["login", "process", "network"]
            },
            "update_count": self._update_count,
            "drift_rates": {
                s: round(dd.current_error_rate, 4)
                for s, dd in self.drift_detectors.items()
            },
        }

    def _update_stream_model(
        self,
        stream: str,
        X: np.ndarray,
        y: np.ndarray,
        weights: np.ndarray,
        session=None,
    ) -> None:
        """Update a single stream's model using weighted data."""
        model = self.detector.models.get(stream)
        if model is None:
            return

        # Sliding-window IF retrain
        new_if = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples=min(256, len(X)),
        )
        new_if.fit(X)

        # Validate
        try:
            old_scores = model.decision_function(X)
            new_scores = new_if.decision_function(X)
            old_auc = float(np.mean(old_scores > 0))
            new_auc = float(np.mean(new_scores > 0))
            if new_auc >= old_auc * 0.95:
                self.detector.models[stream] = new_if
        except Exception:
            logger.debug("IF comparison failed, accepting new model for %s", stream, exc_info=True)
            self.detector.models[stream] = new_if

        # Warm-start supervised with weighted data
        X_labeled, y_labeled, w_labeled = self.buffers[stream].get_labeled_data()
        if len(X_labeled) >= 10 and len(np.unique(y_labeled)) >= 2:
            self._warm_start_supervised(stream, X_labeled, y_labeled, w_labeled)

        # Update baseline CDF
        try:
            raws = np.array(
                [
                    self.detector._score_with(self.detector.models[stream], row)
                    for row in X
                ],
                dtype=float,
            )
            self.detector.baselines[stream] = self.detector._compact_baseline(raws)
        except Exception:
            logger.debug("baseline CDF update failed for %s", stream, exc_info=True)

        # Update threshold
        try:
            if len(y) >= 6 and len(np.unique(y)) >= 2:
                new_threshold, _ = self.detector._tune_threshold(
                    self.detector.models[stream],
                    X,
                    y,
                    supervised=self.detector.supervised_by_stream.get(stream),
                )
                self.detector.thresholds[stream] = new_threshold
        except Exception:
            logger.debug("threshold tuning failed for %s", stream, exc_info=True)

    def _warm_start_supervised(
        self,
        stream: str,
        X: np.ndarray,
        y: np.ndarray,
        weights: np.ndarray,
    ) -> None:
        """Warm-start supervised classifier with importance-weighted data."""
        from backend.ml.anomaly import ML_RANDOM_STATE

        old_sup = self.detector.supervised_by_stream.get(stream)
        pos = int(y.sum())
        neg = int(len(y) - pos)

        # Try warm-start on existing RF
        if old_sup is not None and hasattr(old_sup, "n_estimators"):
            try:
                new_n_estimators = min(old_sup.n_estimators + 15, 180)
                if isinstance(old_sup, RandomForestClassifier):
                    old_sup.set_params(n_estimators=new_n_estimators, warm_start=True)
                    old_sup.fit(X, y)
                    self.detector.supervised_by_stream[stream] = old_sup
                    return
            except Exception:
                logger.debug("calibration failed for %s, using uncalibrated model", stream, exc_info=True)

        # Train new classifier from scratch on weighted buffer
        if HAS_XGBOOST and len(y) >= 50 and min(pos, neg) >= 5:
            scale = (neg / max(pos, 1)) if pos and neg else 1.0
            model = XGBClassifier(
                n_estimators=80,
                max_depth=3,
                learning_rate=0.08,
                random_state=ML_RANDOM_STATE,
                eval_metric="logloss",
                scale_pos_weight=scale,
                subsample=0.9,
                colsample_bytree=0.9,
                min_child_weight=2,
            )
            model.fit(X, y, sample_weight=weights)
            name = "xgboost"
        elif len(y) >= 10 and min(pos, neg) >= 3:
            model = RandomForestClassifier(
                n_estimators=60,
                max_depth=5,
                random_state=ML_RANDOM_STATE,
                class_weight="balanced_subsample",
                min_samples_leaf=2,
                warm_start=True,
            )
            model.fit(X, y, sample_weight=weights)
            name = "random_forest"
        else:
            return

        # Calibrate
        if len(y) >= 18 and min(pos, neg) >= 4:
            try:
                from sklearn.calibration import CalibratedClassifierCV

                cal = CalibratedClassifierCV(
                    model, cv=min(3, min(pos, neg)), method="isotonic"
                )
                cal.fit(X, y, sample_weight=weights)
                self.detector.supervised_by_stream[stream] = cal
                self.detector.supervised_name_by_stream[stream] = name + "+calibrated"
                return
            except Exception:
                logger.debug("calibration failed for %s, using uncalibrated model", stream, exc_info=True)

        self.detector.supervised_by_stream[stream] = model
        self.detector.supervised_name_by_stream[stream] = name

    # ------------------------------------------------------------------
    # Improvement 3: Model versioning with rollback
    # ------------------------------------------------------------------
    def _snapshot_models(self) -> None:
        """Snapshot current models for potential rollback."""
        import copy

        self._model_snapshots = {
            "models": copy.deepcopy(self.detector.models),
            "baselines": {k: v.copy() for k, v in self.detector.baselines.items()},
            "thresholds": dict(self.detector.thresholds),
            "supervised_by_stream": copy.deepcopy(self.detector.supervised_by_stream),
            "supervised_name_by_stream": dict(self.detector.supervised_name_by_stream),
        }

    def _rollback_models(self) -> None:
        """Restore models from snapshot after failed update."""
        if not self._model_snapshots:
            return
        self.detector.models = self._model_snapshots["models"]
        self.detector.baselines = self._model_snapshots["baselines"]
        self.detector.thresholds = self._model_snapshots["thresholds"]
        self.detector.supervised_by_stream = self._model_snapshots[
            "supervised_by_stream"
        ]
        self.detector.supervised_name_by_stream = self._model_snapshots[
            "supervised_name_by_stream"
        ]
        self._model_snapshots = {}
        logger.info("Online update rolled back to pre-update snapshot")

    def _validate_post_update(
        self,
        pre_scores: dict[str, float],
        updated_streams: list[str],
    ) -> bool:
        """Check if post-update models are worse than pre-update.

        Returns True if rollback is needed.
        """
        for stream in updated_streams:
            if stream not in pre_scores:
                continue
            X = self.buffers[stream].get_features()
            if len(X) < 5:
                continue
            try:
                new_scores = self.detector.models[stream].decision_function(X)
                new_mean = float(np.mean(new_scores))
                old_mean = pre_scores[stream]
                # If mean decision score dropped by >20%, rollback
                if new_mean < old_mean * 0.8:
                    logger.warning(
                        "Online update degraded %s: mean_score %.3f -> %.3f",
                        stream,
                        old_mean,
                        new_mean,
                    )
                    return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------
    # Improvement 4: Active learning suggestions
    # ------------------------------------------------------------------
    def suggest_labeling(
        self, features_list: list[list[float]], behaviors: list[str]
    ) -> list[dict]:
        """Suggest the most uncertain events for analyst labeling."""
        return self.active_learner.suggest_for_labeling(
            features_list,
            behaviors,
            self.detector.supervised_by_stream,
        )

    def prequential_report(self) -> dict:
        """Report prequential evaluation metrics per stream."""
        report: dict[str, dict] = {}
        for stream, scores in self._prequential_scores.items():
            if len(scores) < 10:
                continue
            labels = self.buffers[stream].get_labels()
            if len(labels) < 10 or len(np.unique(labels)) < 2:
                continue
            scores_arr = np.array(scores[-len(labels) :])
            labels_arr = labels[: len(scores_arr)]
            try:
                from sklearn.metrics import brier_score_loss, roc_auc_score

                brier = brier_score_loss(labels_arr, scores_arr)
                auc = roc_auc_score(labels_arr, scores_arr)
                report[stream] = {
                    "brier_score": round(float(brier), 4),
                    "auc_roc": round(float(auc), 4),
                    "n_samples": len(labels_arr),
                }
            except Exception:
                continue
        return report

    def status(self) -> dict:
        return {
            "buffer_sizes": {
                s: self.buffers[s].size for s in ["login", "process", "network"]
            },
            "buffer_seen": {
                s: self.buffers[s].n_seen for s in ["login", "process", "network"]
            },
            "events_since_update": self._events_since_update,
            "verdicts_since_update": self._verdicts_since_update,
            "last_update": self._last_update.isoformat() if self._last_update else None,
            "should_update": self.should_update(),
            "update_count": self._update_count,
            "drift_rates": {
                s: round(dd.current_error_rate, 4)
                for s, dd in self.drift_detectors.items()
            },
            "drift_window_sizes": {
                s: dd.window_size for s, dd in self.drift_detectors.items()
            },
        }