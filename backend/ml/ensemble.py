"""Ensemble stacking meta-learner for multi-model fusion.

Phase 2.4: Combines predictions from Isolation Forest (unsupervised),
supervised classifiers (XGBoost/RF), and Markov chain cross-stream
detector into a single stacked prediction via a logistic regression
meta-learner.

The meta-learner is trained on held-out predictions from each base model
to learn optimal blending weights, rather than using fixed 0.6/0.4 ratios.
This allows the system to adaptively weight models based on their actual
performance on the current data distribution.
"""

from __future__ import annotations

import logging

import numpy as np

logger = logging.getLogger("baraq.ml.ensemble")

try:
    from sklearn.linear_model import LogisticRegression

    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False


class EnsembleStacker:
    """Stacking meta-learner that combines IF + supervised + Markov predictions.

    The meta-learner operates as a second-level classifier:
    1. Base models produce prediction scores (IF rank, supervised proba, Markov prob)
    2. These scores are concatenated into a meta-feature vector
    3. A logistic regression meta-learner produces the final fused prediction

    When insufficient labeled data exists for meta-training, falls back to
    the fixed 0.6*IF + 0.4*supervised ratio used by the base system.
    """

    def __init__(self):
        self.meta_model = None
        self.is_trained = False
        self.meta_weights: dict[str, float] = {}
        self._min_samples_for_meta = 30

    def extract_meta_features(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Create meta-feature matrix from base model predictions.

        Args:
            if_scores: IsolationForest rank-calibrated scores [0, 1]
            supervised_probas: Supervised classifier attack probabilities [0, 1]
            markov_scores: Markov chain sequence probabilities [0, 1] (optional)

        Returns:
            Meta-feature matrix of shape (n_samples, n_meta_features)
        """
        n = len(if_scores)
        meta = np.column_stack([if_scores, supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, markov_scores])
        # Add interaction features
        meta = np.column_stack([meta, if_scores * supervised_probas])
        if markov_scores is not None and len(markov_scores) == n:
            meta = np.column_stack([meta, if_scores * markov_scores])
            meta = np.column_stack([meta, supervised_probas * markov_scores])
        return meta

    def train_meta(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None,
        y_true: np.ndarray,
    ) -> dict:
        """Train the meta-learner on held-out base model predictions.

        Returns:
            Training result dict with weights and quality metrics.
        """
        if not HAS_SKLEARN:
            return {"status": "sklearn-not-installed", "trained": False}

        n = len(y_true)
        if n < self._min_samples_for_meta:
            # Fall back to fixed weights
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {
                "status": "insufficient-data",
                "trained": False,
                "fallback_weights": dict(self.meta_weights),
                "min_required": self._min_samples_for_meta,
            }

        meta_X = self.extract_meta_features(if_scores, supervised_probas, markov_scores)

        try:
            self.meta_model = LogisticRegression(
                C=1.0,
                class_weight="balanced",
                max_iter=200,
                random_state=42,
            )
            self.meta_model.fit(meta_X, y_true)
            self.is_trained = True

            # Extract learned weights for interpretability
            coef = self.meta_model.coef_[0]
            self.meta_weights = {
                "if": round(float(coef[0]), 4),
                "supervised": round(float(coef[1]), 4),
                "markov": round(float(coef[2]), 4) if len(coef) > 2 else 0.0,
                "if_x_sup": round(float(coef[-3 if len(coef) > 5 else -1]), 4),
            }

            # Training accuracy
            train_pred = self.meta_model.predict(meta_X)
            train_acc = float(np.mean(train_pred == y_true))

            return {
                "status": "ok",
                "trained": True,
                "weights": dict(self.meta_weights),
                "train_accuracy": round(train_acc, 4),
                "n_samples": n,
            }
        except Exception as e:
            logger.warning("Meta-learner training failed: %s", e)
            self.meta_weights = {"if": 0.6, "supervised": 0.4, "markov": 0.0}
            return {"status": "training-failed", "trained": False, "error": str(e)}

    def predict(
        self,
        if_score: float,
        supervised_proba: float,
        markov_score: float = 0.0,
    ) -> float:
        """Produce fused prediction from base model scores.

        When the meta-learner is trained, uses the logistic regression model.
        Otherwise falls back to fixed 0.6*IF + 0.4*supervised ratio.
        """
        if self.is_trained and self.meta_model is not None:
            meta = np.array(
                [
                    [
                        if_score,
                        supervised_proba,
                        markov_score,
                        if_score * supervised_proba,
                        if_score * markov_score,
                        supervised_proba * markov_score,
                    ]
                ]
            )
            try:
                proba = self.meta_model.predict_proba(meta)[0]
                return float(proba[1]) if len(proba) > 1 else float(proba[0])
            except Exception:
                pass

        # Fallback: fixed ratio
        score = 0.6 * if_score + 0.4 * supervised_proba
        return float(max(0.0, min(1.0, score)))

    def predict_batch(
        self,
        if_scores: np.ndarray,
        supervised_probas: np.ndarray,
        markov_scores: np.ndarray | None = None,
    ) -> np.ndarray:
        """Batch prediction for efficiency."""
        if self.is_trained and self.meta_model is not None:
            meta_X = self.extract_meta_features(
                if_scores, supervised_probas, markov_scores
            )
            try:
                proba = self.meta_model.predict_proba(meta_X)
                return proba[:, 1] if proba.shape[1] > 1 else proba[:, 0]
            except Exception:
                pass

        # Fallback
        scores = 0.6 * if_scores + 0.4 * supervised_probas
        return np.clip(scores, 0.0, 1.0)

    def status(self) -> dict:
        """Current state of the meta-learner."""
        return {
            "is_trained": self.is_trained,
            "has_sklearn": HAS_SKLEARN,
            "meta_weights": dict(self.meta_weights),
            "min_samples_required": self._min_samples_for_meta,
        }
