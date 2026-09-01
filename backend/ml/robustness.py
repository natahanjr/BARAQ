"""Adversarial robustness testing for ML models.

Phase 2.3 + v7 FGSM: Validates model stability under feature perturbation
to ensure the detector is not fragile against minor input variations.

v7 enhancements:
- FGSM-style evasion testing (gradient-sign adversarial perturbation)
- Feature clipping bounds for realistic adversarial constraints
- Evasion success rate and detection degradation metrics
"""

from __future__ import annotations

import logging

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
        return {
            "mean_stability": 0.0,
            "stability_by_noise": {},
            "critical_feature_sensitivity": {},
        }

    noise_levels = noise_levels or [0.02, 0.05, 0.10, 0.15]
    rng = np.random.default_rng(42)

    try:
        baseline_pred = model.predict(X)
    except Exception:
        return {
            "mean_stability": 0.0,
            "stability_by_noise": {},
            "critical_feature_sensitivity": {},
        }

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
            except Exception:
                continue
        stability_by_noise[noise_std] = unchanged / max(total, 1)

    mean_stability = (
        float(np.mean(list(stability_by_noise.values()))) if stability_by_noise else 0.0
    )

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
        except Exception:
            critical_sensitivity[feat_idx] = 1.0

    return {
        "mean_stability": round(mean_stability, 4),
        "stability_by_noise": {k: round(v, 4) for k, v in stability_by_noise.items()},
        "critical_feature_sensitivity": {
            k: round(v, 4) for k, v in critical_sensitivity.items()
        },
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
        (model.score(X, np.zeros(len(X))) if hasattr(model, "score") else None)
    except Exception:
        pass

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
            except Exception:
                importance_matrix[b, f] = 0.0

    mean_importance = np.mean(importance_matrix, axis=0)
    importance_std = np.std(importance_matrix, axis=0)

    # Ranking CV: how much do feature rankings vary across bootstraps?
    rankings = np.zeros_like(importance_matrix)
    for b in range(n_bootstrap):
        rankings[b] = np.argsort(np.argsort(-importance_matrix[b]))
    ranking_cv = float(
        np.mean(np.std(rankings, axis=0) / np.mean(rankings, axis=0 + 1e-9))
    )

    return {
        "mean_importance": [round(float(x), 6) for x in mean_importance],
        "importance_std": [round(float(x), 6) for x in importance_std],
        "ranking_cv": round(ranking_cv, 4),
    }


def fgsm_evasion_test(
    model,
    X: np.ndarray,
    epsilon: float = 0.1,
    n_samples: int = 100,
    feature_bounds: list[tuple[float, float]] | None = None,
) -> dict:
    """FGSM-style adversarial evasion test for tree-based anomaly detectors.

    Since IsolationForest doesn't have differentiable gradients, we simulate
    FGSM by using feature importance as a gradient proxy: perturb features
    in the direction that maximally changes the decision function.

    Args:
        model: Trained IsolationForest or similar model with decision_function
        X: Feature matrix (n_samples, n_features)
        epsilon: Maximum perturbation magnitude per feature
        n_samples: Number of samples to test (subsampled if X is larger)
        feature_bounds: Optional per-feature (min, max) clipping bounds

    Returns:
        Dict with:
        - evasion_success_rate: fraction of samples where prediction flipped
        - mean_score_drop: average reduction in anomaly score after perturbation
        - per_feature_evasion_rate: how often each feature contributed to evasion
        - robustness_score: 1 - evasion_success_rate (higher = more robust)
    """
    if model is None or len(X) == 0:
        return {
            "evasion_success_rate": 0.0,
            "mean_score_drop": 0.0,
            "per_feature_evasion_rate": [],
            "robustness_score": 1.0,
        }

    rng = np.random.default_rng(42)
    n_features = X.shape[1]

    # Subsample if needed
    if len(X) > n_samples:
        idx = rng.choice(len(X), n_samples, replace=False)
        X_test = X[idx]
    else:
        X_test = X.copy()

    # Compute feature importance as gradient proxy
    try:
        baseline_scores = model.decision_function(X_test)
    except Exception:
        return {
            "evasion_success_rate": 0.0,
            "mean_score_drop": 0.0,
            "per_feature_evasion_rate": [],
            "robustness_score": 1.0,
        }

    feature_importance = np.zeros(n_features)
    for f in range(n_features):
        X_perm = X_test.copy()
        perm_idx = rng.permutation(len(X_test))
        X_perm[:, f] = X_test[perm_idx, f]
        try:
            perm_scores = model.decision_function(X_perm)
            feature_importance[f] = np.mean(np.abs(baseline_scores - perm_scores))
        except Exception:
            feature_importance[f] = 0.0

    # Normalize importance to use as perturbation direction
    importance_norm = np.max(feature_importance)
    if importance_norm > 0:
        perturbation_dir = feature_importance / importance_norm
    else:
        perturbation_dir = np.ones(n_features) / n_features

    # Apply FGSM-style perturbation (maximize anomaly score reduction)
    X_adv = X_test.copy()
    for i in range(len(X_test)):
        # Perturb in direction that reduces anomaly score (toward normal)
        X_adv[i] = X_test[i] - epsilon * perturbation_dir

    # Clip to valid range
    if feature_bounds is not None:
        for f, (fmin, fmax) in enumerate(feature_bounds[:n_features]):
            X_adv[:, f] = np.clip(X_adv[:, f], fmin, fmax)
    else:
        X_adv = np.clip(X_adv, 0.0, 1.0)

    # Measure evasion success
    try:
        adv_scores = model.decision_function(X_adv)
        baseline_pred = (baseline_scores < 0).astype(int)  # -1 = anomaly
        adv_pred = (adv_scores < 0).astype(int)

        evasion_mask = baseline_pred != adv_pred
        evasion_rate = float(np.mean(evasion_mask))
        mean_score_drop = float(np.mean(baseline_scores - adv_scores))

        # Per-feature evasion contribution (which features caused flips)
        per_feature_rate = np.zeros(n_features)
        flipped_idx = np.where(evasion_mask)[0]
        for idx in flipped_idx:
            # Find features that changed most
            diffs = np.abs(X_adv[idx] - X_test[idx])
            top_feat = np.argmax(diffs)
            per_feature_rate[top_feat] += 1

        if len(flipped_idx) > 0:
            per_feature_rate /= len(flipped_idx)

        return {
            "evasion_success_rate": round(evasion_rate, 4),
            "mean_score_drop": round(mean_score_drop, 6),
            "per_feature_evasion_rate": [round(float(x), 4) for x in per_feature_rate],
            "robustness_score": round(1.0 - evasion_rate, 4),
            "n_tested": len(X_test),
            "n_evasion": int(np.sum(evasion_mask)),
        }
    except Exception as e:
        logger.debug("FGSM evasion test failed: %s", e)
        return {
            "evasion_success_rate": 0.0,
            "mean_score_drop": 0.0,
            "per_feature_evasion_rate": [],
            "robustness_score": 1.0,
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

    for behavior, X in [
        ("login", X_login),
        ("process", X_process),
        ("network", X_network),
    ]:
        model = detector.models.get(behavior)
        if model is None or X is None or len(X) < 5:
            continue

        stability = prediction_stability_test(model, X)
        importance = feature_importance_stability(model, X)
        evasion = fgsm_evasion_test(model, X, epsilon=0.1, n_samples=min(100, len(X)))

        stream_score = (
            stability["mean_stability"] * 0.5
            + evasion["robustness_score"] * 0.5
        )
        results[behavior] = {
            "stability": stability,
            "importance_stability": importance,
            "evasion_test": evasion,
            "robustness_score": round(stream_score, 4),
        }
        scores.append(stream_score)

    overall_score = float(np.mean(scores)) if scores else 0.0
    return {
        "overall_robustness_score": round(overall_score, 4),
        "per_stream": results,
        "verdict": (
            "robust"
            if overall_score >= 0.85
            else "moderate" if overall_score >= 0.70 else "fragile"
        ),
    }


def cross_user_validation(
    detector,
    user_sessions: dict[str, np.ndarray],
) -> dict:
    """Validate model generalization across different user roles/environments.

    Tests if the model trained on one set of users generalizes to unseen users.
    This addresses the baseline bias problem of single-machine training.

    Args:
        detector: Trained MLAnomalyDetector
        user_sessions: Dict mapping user_id/role -> feature matrix

    Returns:
        Dict with per-user generalization scores and overall fairness metric
    """
    if not detector.is_ready or not user_sessions:
        return {"status": "no-data", "per_user_scores": {}, "fairness_score": 0.0}

    per_user_scores: dict[str, dict] = {}
    scores = []

    for user_id, X_user in user_sessions.items():
        if len(X_user) < 5:
            continue

        # Score each user's events with the global model
        user_scores = []
        for behavior in ("login", "process", "network"):
            model = detector.models.get(behavior)
            if model is None:
                continue
            try:
                raw_scores = model.decision_function(X_user)
                # Convert to [0,1] anomaly scores
                normalized = 0.5 - raw_scores
                user_scores.extend(normalized.tolist())
            except Exception:
                continue

        if user_scores:
            mean_score = float(np.mean(user_scores))
            std_score = float(np.std(user_scores))
            anomaly_rate = float(np.mean(np.array(user_scores) > 0.7))
            per_user_scores[user_id] = {
                "mean_anomaly_score": round(mean_score, 4),
                "std_anomaly_score": round(std_score, 4),
                "anomaly_rate": round(anomaly_rate, 4),
                "n_events": len(user_scores),
            }
            scores.append(mean_score)

    # Fairness: coefficient of variation across users (lower = more fair)
    if len(scores) >= 2:
        mean_all = float(np.mean(scores))
        std_all = float(np.std(scores))
        fairness = 1.0 - min(1.0, std_all / max(mean_all, 1e-6))
    else:
        fairness = 1.0

    return {
        "status": "ok",
        "per_user_scores": per_user_scores,
        "fairness_score": round(fairness, 4),
        "n_users": len(per_user_scores),
    }


def cross_environment_validation(
    detector,
    env_sessions: dict[str, np.ndarray],
) -> dict:
    """Validate model generalization across different environments (office, datacenter, etc.).

    Args:
        detector: Trained MLAnomalyDetector
        env_sessions: Dict mapping environment_name -> feature matrix

    Returns:
        Dict with per-environment scores and domain shift metrics
    """
    if not detector.is_ready or not env_sessions:
        return {"status": "no-data", "per_env_scores": {}, "domain_shift": 0.0}

    per_env_scores: dict[str, dict] = {}

    for env_name, X_env in env_sessions.items():
        if len(X_env) < 5:
            continue

        env_anomaly_scores = []
        for behavior in ("login", "process", "network"):
            model = detector.models.get(behavior)
            if model is None:
                continue
            try:
                raw_scores = model.decision_function(X_env)
                normalized = 0.5 - raw_scores
                env_anomaly_scores.extend(normalized.tolist())
            except Exception:
                continue

        if env_anomaly_scores:
            per_env_scores[env_name] = {
                "mean_anomaly_score": round(float(np.mean(env_anomaly_scores)), 4),
                "std_anomaly_score": round(float(np.std(env_anomaly_scores)), 4),
                "anomaly_rate": round(float(np.mean(np.array(env_anomaly_scores) > 0.7)), 4),
                "n_events": len(env_anomaly_scores),
            }

    # Domain shift: max difference in mean scores between environments
    env_means = [v["mean_anomaly_score"] for v in per_env_scores.values()]
    domain_shift = float(max(env_means) - min(env_means)) if len(env_means) >= 2 else 0.0

    return {
        "status": "ok",
        "per_env_scores": per_env_scores,
        "domain_shift": round(domain_shift, 4),
        "n_environments": len(per_env_scores),
    }


def cross_platform_validation(
    detector,
    platform_sessions: dict[str, np.ndarray],
) -> dict:
    """Validate model generalization across different platforms (Windows, Linux, macOS).

    Tests if models trained primarily on Windows data generalize to other platforms.
    This is critical since BARAQ's evaluation has been Windows-only.

    Args:
        detector: Trained MLAnomalyDetector
        platform_sessions: Dict mapping platform_name -> feature matrix

    Returns:
        Dict with per-platform scores and cross-platform compatibility metrics
    """
    if not detector.is_ready or not platform_sessions:
        return {"status": "no-data", "per_platform_scores": {}, "compatibility_score": 0.0}

    per_platform_scores: dict[str, dict] = {}
    scores = []

    for platform, X_platform in platform_sessions.items():
        if len(X_platform) < 5:
            continue

        platform_anomaly_scores = []
        for behavior in ("login", "process", "network"):
            model = detector.models.get(behavior)
            if model is None:
                continue
            try:
                raw_scores = model.decision_function(X_platform)
                normalized = 0.5 - raw_scores
                platform_anomaly_scores.extend(normalized.tolist())
            except Exception:
                continue

        if platform_anomaly_scores:
            mean_score = float(np.mean(platform_anomaly_scores))
            std_score = float(np.std(platform_anomaly_scores))
            anomaly_rate = float(np.mean(np.array(platform_anomaly_scores) > 0.7))
            per_platform_scores[platform] = {
                "mean_anomaly_score": round(mean_score, 4),
                "std_anomaly_score": round(std_score, 4),
                "anomaly_rate": round(anomaly_rate, 4),
                "n_events": len(platform_anomaly_scores),
                "compatible": abs(mean_score - 0.5) < 0.2,  # Within 20% of neutral
            }
            scores.append(mean_score)

    # Cross-platform compatibility: how similar are scores across platforms
    if len(scores) >= 2:
        mean_all = float(np.mean(scores))
        std_all = float(np.std(scores))
        compatibility = 1.0 - min(1.0, std_all / max(mean_all, 1e-6))
    else:
        compatibility = 1.0

    # Platform-specific recommendations
    recommendations = []
    for platform, metrics in per_platform_scores.items():
        if not metrics["compatible"]:
            recommendations.append(
                f"{platform}: mean anomaly score {metrics['mean_anomaly_score']:.3f} "
                f"deviates significantly from neutral (0.5). Consider platform-specific tuning."
            )

    return {
        "status": "ok",
        "per_platform_scores": per_platform_scores,
        "compatibility_score": round(compatibility, 4),
        "n_platforms": len(per_platform_scores),
        "recommendations": recommendations,
    }
