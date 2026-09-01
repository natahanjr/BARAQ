"""Ensemble stacking meta-learner for multi-model fusion.

Phase 2.4 + v7/v8 enhancements: Combines predictions from Isolation Forest
(unsupervised), supervised classifiers (XGBoost/RF), and Markov chain
cross-stream detector into a single stacked prediction via a meta-learner.

v7 enhancements:
- Gradient boosting meta-learner as alternative to logistic regression
- Feature-level fusion with cross-model interaction features
- Confidence-weighted blending based on base model agreement

v8 enhancements:
- Time-window ensemble: multiple models trained on different time windows
- Weighted voting based on model recency and performance
"""

from __future__ import annotations

import logging
from collections import deque

import numpy as np

logger = logging.getLogger("baraq.ml.ensemble")

try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False


class TimeWindowEnsemble:
    """Ensemble of models trained on different time windows.

    Maintains a sliding window of models trained at different time points.
    Newer models get higher weight, but older models provide stability
    against temporal bias.
    """

    def __init__(self, max_windows: int = 5, decay_factor: float = 0.8):
        self.max_windows = max_windows
        self.decay_factor = decay_factor
        self._windows: deque = deque(maxlen=max_windows)
        self._window_weights: deque = deque(maxlen=max_windows)

    def add_model(self, model, window_start, window_end, performance_score: float = 1.0):
        """Add a trained model for a specific time window."""
        self._windows.append({
            "model": model,
            "start": window_start,
            "end": window_end,
            "performance": performance_score,
        })
        # Weight by recency (newer = higher weight)
        n = len(self._windows)
        weights = [self.decay_factor ** (n - 1 - i) for i in range(n)]
        # Normalize weights
        total = sum(weights)
        self._window_weights = [w / total for w in weights] if total > 0 else weights

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Weighted average prediction across all time window models."""
        if not self._windows:
            return np.zeros(len(X))

        predictions = []
        for i, window in enumerate(self._windows):
            try:
                scores = window["model"].decision_function(X)
                # Normalize to [0, 1]
                normalized = 0.5 - scores
                predictions.append(normalized * self._window_weights[i])
            except Exception:
                continue

        if not predictions:
            return np.zeros(len(X))

        return np.sum(predictions, axis=0)

    def predict_single(self, features: list[float]) -> float:
        """Predict for a single sample."""
        X = np.array([features])
        result = self.predict(X)
        return float(result[0]) if len(result) > 0 else 0.0

    def get_window_info(self) -> list[dict]:
        """Get information about active time windows."""
        return [
            {
                "start": w["start"],
                "end": w["end"],
                "performance": w["performance"],
                "weight": self._window_weights[i] if i < len(self._window_weights) else 0.0,
            }
            for i, w in enumerate(self._windows)
        ]

    @property
    def n_windows(self) -> int:
        return len(self._windows)


class EnsembleStacker:
    """Stacking meta-learner that combines IF + supervised + Markov predictions.

    v7 enhancements:
    - Gradient boosting meta-learner for non-linear blending
    - Feature-level fusion with model agreement signals
    - Confidence-weighted fallback blending
    """

    def __init__(self):
        self.meta_model = None
        self.gb_model = None
        self.is_trained = False
        self.meta_weights: dict[str, float] = {}
        self._min_samples_for_meta = 30
        self._use_gradient_boosting = True

    def extract_meta_features(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Create meta-feature matrix from base model predictions with feature-level fusion.

        Features:
        - Raw scores from each model
        - Pairwise interactions (IF*Sup, IF*Markov, Sup*Markov)
        - Agreement signals (model agreement binary features)
        - Variance of model predictions
        """
        n = len(if_scores)
        meta = np.column_stack([if_scores, supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, markov_scores])

        # Pairwise interaction features
        meta = np.column_stack([meta, if_scores * supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, if_scores * markov_scores])
            meta = np.column_stack([meta, supervised_probas * markov_scores])

            # v7: Model agreement signals
            if_threshold = 0.5
            sup_threshold = 0.5
            mark_threshold = 0.5
            if_agree = ((if_scores > if_threshold) == (supervised_probas > sup_threshold)).astype(float)
            all_agree = ((if_scores > if_threshold) &
                         (supervised_probas > sup_threshold) &
                         (markov_scores > mark_threshold)).astype(float)
            any_anomaly = ((if_scores > if_threshold) |
                           (supervised_probas > sup_threshold) |
                           (markov_scores > mark_threshold)).astype(float)
            meta = np.column_stack([meta, if_agree, all_agree, any_anomaly])

            # v7: Prediction variance (disagreement signal)
            all_scores = np.column_stack([if_scores, supervised_probas, markov_scores])
            pred_variance = np.var(all_scores, axis=1)
            meta = np.column_stack([meta, pred_variance])

        return meta

    def train_meta(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None,
        y_true: np.ndarray,
    ) -> dict:
        """Train the meta-learner on held-out base model predictions.

        v7: Tries both logistic regression and gradient boosting, keeps the better one.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        n = len(y_true)
        if n < self._min_samples_for_meta:
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {
                "status": "insufficient-data",
                "trained": False,
                "fallback_weights": dict(self.meta_weights),
                "min_required": self._min_samples_for_meta,
            }

        meta_X = self.extract_meta_features(if_scores, supervised_probas, markov_scores)

        results = {}

        # Try logistic regression
        try:
            lr_model = LogisticRegression(
                C=1.0, class_weight="balanced", max_iter=200, random_state=42,
            )
            lr_model.fit(meta_X, y_true)
            lr_train_acc = float(np.mean(lr_model.predict(meta_X) == y_true))
            results["logistic_regression"] = {"model": lr_model, "accuracy": lr_train_acc}
        except Exception as e:
            logger.debug("Logistic regression meta-learner failed: %s", e)

        # v7: Try gradient boosting
        if self._use_gradient_boosting:
            try:
                gb_model = GradientBoostingClassifier(
                    n_estimators=50,
                    max_depth=3,
                    learning_rate=0.1,
                    random_state=42,
                )
                gb_model.fit(meta_X, y_true)
                gb_train_acc = float(np.mean(gb_model.predict(meta_X) == y_true))
                results["gradient_boosting"] = {"model": gb_model, "accuracy": gb_train_acc}
            except Exception as e:
                logger.debug("Gradient boosting meta-learner failed: %s", e)

        if not results:
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {"status": "training-failed", "trained": False, "error": "all meta-learners failed"}

        # Pick best model by training accuracy
        best_name = max(results, key=lambda k: results[k]["accuracy"])
        best_result = results[best_name]

        if best_name == "gradient_boosting":
            self.gb_model = best_result["model"]
            self.meta_model = None
        else:
            self.meta_model = best_result["model"]
            self.gb_model = None

        self.is_trained = True

        # Extract learned weights for interpretability
        if self.meta_model is not None:
            coef = self.meta_model.coef_[0]
            self.meta_weights = {
                "if": round(float(coef[0]), 4),
                "supervised": round(float(coef[1]), 4),
                "markov": round(float(coef[2]), 4) if len(coef) > 2 else 0.0,
            }
        else:
            self.meta_weights = {"meta_learner": best_name}

        return {
            "status": "ok",
            "trained": True,
            "meta_learner": best_name,
            "weights": dict(self.meta_weights),
            "train_accuracy": round(best_result["accuracy"], 4),
            "n_samples": n,
            "candidates": {k: round(v["accuracy"], 4) for k, v in results.items()},
        }

    def predict(
        self,
        if_score: float,
        supervised_proba: float,
        markov_score: float = 0.0,
    ) -> float:
        """Produce fused prediction from base model scores.

        v7: Uses gradient boosting when available, falls back to logistic regression,
        then to confidence-weighted blending.
        """
        meta = np.array(
            [[
                if_score, supervised_proba, markov_score,
                if_score * supervised_proba,
                if_score * markov_score,
                supervised_proba * markov_score,
            ]]
        )

        # Add v7 agreement features when markov available
        if markov_score != 0.0:
            if_agree = float((if_score > 0.5) == (supervised_proba > 0.5))
            all_agree = float((if_score > 0.5) and (supervised_proba > 0.5) and (markov_score > 0.5))
            any_anomaly = float((if_score > 0.5) or (supervised_proba > 0.5) or (markov_score > 0.5))
            pred_var = float(np.var([if_score, supervised_proba, markov_score]))
            meta = np.column_stack([meta, [[if_agree, all_agree, any_anomaly, pred_var]]])

        # Try gradient boosting first
        if self.gb_model is not None:
            try:
                proba = self.gb_model.predict_proba(meta)[0]
                return float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                pass

        # Try logistic regression
        if self.meta_model is not None:
            try:
                proba = self.meta_model.predict_proba(meta)[0]
                return float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                pass

        # v7: Confidence-weighted fallback
        weights = {"if": 0.5, "supervised": 0.35, "markov": 0.15}
        if markov_score == 0.0:
            weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}

        score = (
            weights["if"] * if_score
            + weights["supervised"] * supervised_proba
            + weights["markov"] * markov_score
        )
        return float(max(0.0, min(1.0, score)))

    def predict_batch(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Batch prediction for efficiency."""
        if self.is_trained:
            meta_X = self.extract_meta_features(if_scores, supervised_probas, markov_scores)

            # Try gradient boosting first
            if self.gb_model is not None:
                try:
                    proba = self.gb_model.predict_proba(meta_X)
                    return proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
                except Exception:
                    pass

            # Try logistic regression
            if self.meta_model is not None:
                try:
                    proba = self.meta_model.predict_proba(meta_X)
                    return proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
                except Exception:
                    pass

        # v7: Confidence-weighted fallback
        if markov_scores is not None and len(markov_scores) == len(if_scores):
            scores = 0.5 * if_scores + 0.35 * supervised_probas + 0.15 * markov_scores
        else:
            scores = 0.6 * if_scores + 0.4 * supervised_probas
        return np.clip(scores, 0.0, 1.0)

    def status(self) -> dict:
        """Current state of the meta-learner."""
        active_model = "none"
        if self.gb_model is not None:
            active_model = "gradient_boosting"
        elif self.meta_model is not None:
            active_model = "logistic_regression"

        return {
            "is_trained": self.is_trained,
            "has_sklearn": HAS_SKLEARN,
            "active_meta_learner": active_model,
            "meta_weights": dict(self.meta_weights),
            "min_samples_required": self._min_samples_for_meta,
        }
