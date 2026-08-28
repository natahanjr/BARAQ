"""Adversarial robustness testing for ML models.

Phase 2.3: Validates model stability under feature perturbation to ensure
the detector is not fragile against minor input variations (e.g., timestamp
drift, feature noise, or adversarial feature manipulation).

The robustness module:
1. Tests prediction stability under Gaussian feature noise
2. Measures decision boundary sensitivity to individual feature perturbations
3. Validates that critical features (event_id, threat intel) maintain prediction consistency
4. Provides a robustness score for model selection and monitoring
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger("baraq.ml.robustness")


def _perturb_features(
    X: np.ndarray,
    noise_std: float = 0.05,
    rng: np.random.Generator | None = None,
) -> np.ndarray:
    """Apply Gaussian noise perturbation to feature matrix.

    Args:
        X: Feature matrix (n_samples, n_features)
        noise_std: Standard deviation of noise relative to feature range
        rng: Random number generator for reproducibility

    Returns:
        Perturbed feature matrix of same shape
    """
    rng = rng or np.random.default_rng(42)
    noise = rng.normal(0.0, noise_std, size=X.shape)
    return np.clip(X + noise, 0.0, 1.0)


def prediction_stability_test(
    model,
    X: np.ndarray,
    n_perturbations: int = 10,
    noise_levels: list[float] | None = None,
) -> dict:
    """Test prediction stability under feature perturbation.

    Measures how often the model's prediction changes when small noise is
    added to the input features. A robust model should maintain consistent
    predictions under minor perturbations.

    Returns:
        Dict with stability metrics:
        - mean_stability: fraction of predictions unchanged (0-1, higher = more stable)
        - stability_by_noise: stability at each noise level
        - critical_feature_sensitivity: dict of per-feature sensitivity scores
    """
    if model is None or len(X) == 0:
        return {"mean_stability": 0.0, "stability_by_noise": {}, "critical_feature_sensitivity": {}}

    noise_levels = noise_levels or [0.02, 0.05, 0.10, 0.15]
    rng = np.random.default_rng(42)

    try:
        baseline_pred = model.predict(X)
    except Exception:  # noqa: BLE001
        return {"mean_stability": 0.0, "stability_by_noise": {}, "critical_feature_sensitivity": {}}

    stability_by_noise: dict[float, float] = {}
    for noise_std in noise_levels:
        unchanged = 0
        total = 0
        for _ in range(n_perturbations):
            X_perturbed = _perturb_features(X, noise_std=noise_std, rng=rng)
            try:
                perturbed_pred = model.predict(X_perturbed)
                unchanged += int(np.sum(perturbed_pred == baseline_pred))
                total += len(baseline_pred)
            except Exception:  # noqa: BLE001
                continue
        stability_by_noise[noise_std] = unchanged / max(total, 1)

    mean_stability = float(np.mean(list(stability_by_noise.values()))) if stability_by_noise else 0.0

    # Critical feature sensitivity analysis
    n_features = X.shape[1]
    critical_sensitivity: dict[int, float] = {}
    critical_indices = [0, 13, 14]  # event_id, threat_intel_score (login stream)
    for feat_idx in critical_indices:
        if feat_idx >= n_features:
            continue
        X_perturbed = X.copy()
        X_perturbed[:, feat_idx] = np.clip(X[:, feat_idx] + 0.1, 0.0, 1.0)
        try:
            base_pred = model.predict(X)
            perturbed_pred = model.predict(X_perturbed)
            flip_rate = float(np.mean(base_pred != perturbed_pred))
            critical_sensitivity[feat_idx] = flip_rate
        except Exception:  # noqa: BLE001
            critical_sensitivity[feat_idx] = 1.0

    return {
        "mean_stability": round(mean_stability, 4),
        "stability_by_noise": {k: round(v, 4) for k, v in stability_by_noise.items()},
        "critical_feature_sensitivity": {k: round(v, 4) for k, v in critical_sensitivity.items()},
    }


def feature_importance_stability(
    model,
    X: np.ndarray,
    n_bootstrap: int = 20,
) -> dict:
    """Measure feature importance stability via bootstrap resampling.

    Uses permutation importance on bootstrap samples to check if feature
    importance rankings are stable. High variance in rankings suggests the
    model may be overfitting to spurious correlations.

    Returns:
        Dict with:
        - mean_importance: mean importance per feature
        - importance_std: std of importance per feature
        - ranking_cv: coefficient of variation of feature rankings (lower = more stable)
    """
    if model is None or len(X) < 10:
        n_features = X.shape[1] if X is not None and len(X) > 0 else 0
        return {
            "mean_importance": [0.0] * n_features,
            "importance_std": [0.0] * n_features,
            "ranking_cv": 1.0,
        }

    n_features = X.shape[1]
    rng = np.random.default_rng(42)
    importance_matrix = np.zeros((n_bootstrap, n_features))

    try:
        baseline_score = model.score(X, np.zeros(len(X))) if hasattr(model, 'score') else None
    except Exception:  # noqa: BLE001
        baseline_score = None

    for b in range(n_bootstrap):
        idx = rng.choice(len(X), size=len(X), replace=True)
        X_boot = X[idx]
        for f in range(n_features):
            X_perm = X_boot.copy()
            rng.shuffle(X_perm[:, f])
            try:
                # Use decision_function magnitude as importance proxy
                base_dec = np.mean(np.abs(model.decision_function(X_boot)))
                perm_dec = np.mean(np.abs(model.decision_function(X_perm)))
                importance_matrix[b, f] = abs(base_dec - perm_dec)
            except Exception:  # noqa: BLE001
                importance_matrix[b, f] = 0.0

    mean_importance = np.mean(importance_matrix, axis=0)
    importance_std = np.std(importance_matrix, axis=0)

    # Ranking CV: how much do feature rankings vary across bootstraps?
    rankings = np.zeros_like(importance_matrix)
    for b in range(n_bootstrap):
        rankings[b] = np.argsort(np.argsort(-importance_matrix[b]))
    ranking_cv = float(np.mean(np.std(rankings, axis=0) / np.mean(rankings, axis=0 + 1e-9)))

    return {
        "mean_importance": [round(float(x), 6) for x in mean_importance],
        "importance_std": [round(float(x), 6) for x in importance_std],
        "ranking_cv": round(ranking_cv, 4),
    }


def evaluate_robustness(
    detector,
    X_login: np.ndarray | None = None,
    X_process: np.ndarray | None = None,
    X_network: np.ndarray | None = None,
) -> dict:
    """Full robustness evaluation across all trained streams.

    Runs stability tests and feature importance analysis on each stream's
    Isolation Forest model and returns aggregated metrics.

    Returns:
        Dict with per-stream robustness results and an overall score.
    """
    results: dict[str, dict] = {}
    scores: list[float] = []

    for behavior, X in [("login", X_login), ("process", X_process), ("network", X_network)]:
        model = detector.models.get(behavior)
        if model is None or X is None or len(X) < 5:
            continue

        stability = prediction_stability_test(model, X)
        importance = feature_importance_stability(model, X)

        stream_score = stability["mean_stability"]
        results[behavior] = {
            "stability": stability,
            "importance_stability": importance,
            "robustness_score": round(stream_score, 4),
        }
        scores.append(stream_score)

    overall_score = float(np.mean(scores)) if scores else 0.0
    return {
        "overall_robustness_score": round(overall_score, 4),
        "per_stream": results,
        "verdict": "robust" if overall_score >= 0.85 else "moderate" if overall_score >= 0.70 else "fragile",
    }
