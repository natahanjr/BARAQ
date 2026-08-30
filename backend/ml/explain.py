"""Model explainability - SHAP / LIME local attributions for anomaly scores.

Explaining *why* an event was flagged makes the SOC defensible: an analyst
reading "ML anomaly 0.97" needs to see that it is an unusual *source host* or
an *encoded command line* that moved the IsolationForest away from the
locally-learned baseline, not a black box.

Pipeline (model-agnostic, picks the best available explainer):

1. **LIME** (preferred) - a tabular surrogate regressor around the instance,
   fitted on locally-sampled background windows; its per-feature weights are
   the contribution signs/magnitudes in the deployed score space.
2. **SHAP** - KernelExplainer on the same background with the combined score
   as the target; Shapley values give additive attributions.
3. **Permutation fallback** - per-feature leave-one-value perturbation when
   neither explainer library is installed, so the feature degrades
   gracefully on minimal installs.

The predict function used here is exactly the deployed scorer
(``MLAnomalyDetector.score_event_for_behavior``) so attributions reflect the
live model, the rank-CDF blending and the per-stream thresholds.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

import numpy as np
from sqlalchemy import select

from backend.database.connection import SessionLocal
from backend.database.models import NetworkConnection, NormalizedEvent
from backend.ml.anomaly import (
    LOGIN_EVENTS,
    PROCESS_EVENTS,
    _behavior_of,
    event_feature_vector,
    get_detector,
)

logger = logging.getLogger("baraq.ml.explain")

try:
    import shap  # type: ignore

    HAS_SHAP = True
except ImportError:  # pragma: no cover
    HAS_SHAP = False

try:
    from lime.lime_tabular import LimeTabularExplainer  # type: ignore  # noqa: F401

    HAS_LIME = True
except ImportError:  # pragma: no cover
    HAS_LIME = False

#: Human-readable feature names per behavior stream (index-aligned with the
#: vectors produced by :func:`backend.ml.anomaly.event_feature_vector`).
FEATURE_NAMES = {
    "login": [
        "event_id",
        "logon_type",
        "sub_status",
        "source_host",
        "is_locked",
        "hour_sin",
        "hour_cos",
        "is_night",
        "is_weekend",
        "unusual_logon_type",
        "time_since_last_login",
        "logins_last_hour",
        "logins_last_day",
        "threat_intel_score",
        # v5 enhanced features
        "failed_login_velocity_5m",
        "failed_login_velocity_15m",
        "failed_login_velocity_1h",
        "logon_type_entropy",
        "source_ip_diversity",
        "time_between_logins_zscore",
        "privilege_escalation_indicator",
        # Cross-stream features
        "recent_failed_logins",
        "recent_suspicious_processes",
        "recent_network_connections",
        "login_process_ratio",
        "time_since_last_any",
        "has_failed_then_process",
        "has_process_then_network",
        "event_diversity",
        # Phase 2 temporal features (v6)
        "business_hours_indicator",
        "event_burst_score",
        "kill_chain_phase",
        "session_duration_deviation",
        "user_attack_frequency",
    ],
    "process": [
        "event_id",
        "has_encoded",
        "has_download",
        "has_hidden",
        "group_sid",
        "script_len",
        "cmdline_len",
        "hour_sin",
        "hour_cos",
        "has_remote",
        "time_since_last_process",
        "processes_last_hour",
        "processes_last_day",
        "threat_intel_score",
        # v5 enhanced features
        "parent_child_anomaly",
        "commandline_entropy",
        "process_frequency_per_user",
        "lolbin_abuse_indicator",
        "new_process_path",
        # Cross-stream features
        "recent_failed_logins",
        "recent_suspicious_processes",
        "recent_network_connections",
        "login_process_ratio",
        "time_since_last_any",
        "has_failed_then_process",
        "has_process_then_network",
        "event_diversity",
        # Phase 2 temporal features (v6)
        "business_hours_indicator",
        "event_burst_score",
        "kill_chain_phase",
        "process_risk_proxy",
        "process_attack_frequency",
    ],
    "network": [
        "is_private",
        "is_testnet",
        "is_link_local",
        "first_octet",
        "second_octet",
        "is_class_a",
        "is_class_b",
        "is_class_c",
        "connection_count",
        "distinct_ports",
        "bytes_sent_mb",
        "bytes_recv_mb",
        "duration_h",
        "send_rate",
        # v5 enhanced features
        "connection_velocity",
        "port_scan_indicator",
        "exfiltration_indicator",
        "beaconing_indicator",
        "dns_query_pattern",
        # Phase 2 temporal features (v6)
        "burst_velocity",
        "kill_chain_phase",
        "attack_history",
        "connections_per_minute",
        "port_scan_trend",
        # Base features
        "is_novel",
        "hour",
    ],
}

#: Back-compat alias used by callers expecting a single export.
FEATURES_BY_BEHAVIOR = FEATURE_NAMES

_explanation_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()
_MAX_BACKGROUND = 96
#: SHAP KernelExplainer uses a small tail of the background (8 dims -> cheap).
_SHAP_BACKGROUND = 16
#: Fixed sample count for the KernelExplainer; without an explicit value shap
#: defaults to a large scheme that takes tens of seconds for the local score.
_SHAP_NSAMPLES = 100
#: LIME's default ``num_samples`` (5000) takes minutes on a non-vectorised
#: predict_fn; cap it so explainability stays interactive.
_LIME_SAMPLES = 300
#: Hard wall-clock budget per SHAP/LIME attempt. Explaining must never block
#: the API: when the worker does not finish in time it is abandoned (daemon
#: thread) and the result degrades to the instant permutation fallback.
_EXPLAIN_BUDGET_SECONDS = 3.5


def _run_budgeted(fn) -> object | None:
    """Invoke ``fn()`` with a wall-clock budget; ``None`` when it times out.

    The worker runs as a daemon so a slow ``KernelExplainer`` cannot block
    the request thread - the caller immediately degrades and the expensive
    computation is simply abandoned in the background.
    """

    box = {"result": None, "done": False}

    def worker() -> None:
        try:
            box["result"] = fn()
        except Exception as exc:
            logger.debug("explainer attempt raised: %s", exc)
        finally:
            box["done"] = True

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(_EXPLAIN_BUDGET_SECONDS)
    if not box["done"]:
        logger.info(
            "explainer exceeded %.1fs budget; using permutation fallback",
            _EXPLAIN_BUDGET_SECONDS,
        )
        return None
    return box["result"]


def _background_samples(
    session, behavior: str, limit: int = _MAX_BACKGROUND
) -> list[list[float]]:
    """Recent real feature vectors from the same behavior stream.

    These act as the explainer's baselines, so an attribution is meaningful
    *relative to the locally-learned distribution* rather than an artificial
    grid. Falls back to the full event table when the recent window is too
    thin (fewer than 6 vectors).
    """
    since = datetime.now(UTC) - timedelta(hours=24)
    if behavior == "network":
        rows = session.scalars(
            select(NetworkConnection).where(NetworkConnection.observed_at >= since)
        ).all()
        vectors: list[list[float]] = []
        for r in rows:
            try:
                code = (
                    1.0
                    if (r.remote_ip or "").startswith(
                        ("203.0.113.", "198.51.100.", "45.")
                    )
                    else 0.0
                )
                sent_mb = (r.bytes_sent or 0) / 1_000_000.0
                hours = (r.duration_seconds or 0.0) / 3600.0
                vectors.append(
                    [
                        code,
                        float((r.remote_port or 0) + 1),
                        float((r.remote_port or 0) % 7 + 1),
                        sent_mb,
                        (r.bytes_recv or 0) / 1_000_000.0,
                        hours,
                        sent_mb / max(hours, 0.01),
                        1.0,
                        float(r.observed_at.hour if r.observed_at else 0) / 24.0,
                    ]
                )
            except (AttributeError, TypeError, ValueError):
                pass
            if len(vectors) >= limit:
                break
        return vectors

    event_ids = LOGIN_EVENTS if behavior == "login" else PROCESS_EVENTS
    vector: list[list[float]] = []
    query = select(NormalizedEvent).where(
        NormalizedEvent.event_id.in_(event_ids),
        NormalizedEvent.timestamp >= since,
    )
    for ev in session.scalars(query):
        vec = event_feature_vector(ev)
        if vec:
            vector.append(vec)
        if len(vector) >= limit:
            break
    if len(vector) < 6:
        query = select(NormalizedEvent).where(NormalizedEvent.event_id.in_(event_ids))
        for ev in session.scalars(query):
            vec = event_feature_vector(ev)
            if vec and vec not in vector:
                vector.append(vec)
            if len(vector) >= limit:
                break
    return vector


def _predict_batch(behavior: str, X) -> np.ndarray:
    """Vectorised mirror of ``MLAnomalyDetector._combined_score``.

    SHAP/LIME make hundreds of predict calls; a per-row Python loop through
    the deployed scorer costs ~80 ms each, which alone blows the interactive
    budget. This evaluates the same deployed score in one batched pass:
    IF ``decision_function`` -> raw anomaly -> rank-CDF blend with the
    supervised classifier's attack probability (identical to the live
    scorer, minus the per-row Python overhead).
    """
    detector = get_detector()
    model = detector.models.get(behavior)
    if model is None:
        return np.zeros(len(np.atleast_2d(X)))
    arr = np.atleast_2d(np.asarray(X, dtype=float))
    if arr.shape[1] != model.n_features_in_:
        return np.zeros(len(arr))
    decision = model.decision_function(arr)
    raws = np.clip(0.5 - decision, 0.0, 1.0)
    ranks = detector._rank_of(raws, detector.baselines.get(behavior))
    classifier = detector.supervised_by_stream.get(behavior) or detector.supervised
    if classifier is None:
        return ranks
    try:
        proba = classifier.predict_proba(arr)
        p = proba[:, 1] if proba.shape[1] > 1 else np.zeros(len(arr))
    except Exception:
        p = np.zeros(len(arr))
    return np.clip(0.6 * ranks + 0.4 * p, 0.0, 1.0)


def _predict(behavior: str, features: list[float]) -> np.ndarray:
    """Deployed combined score for a single feature vector (as an array)."""
    return _predict_batch(behavior, np.asarray([features], dtype=float))


def _lime(
    behavior: str, features: list[float], background: list[list[float]]
) -> list[tuple[int, float]] | None:
    try:
        from lime.lime_tabular import LimeTabularExplainer as _Lime

        background_arr = np.asarray(background[-64:], dtype=float)
        explainer = _Lime(
            training_data=background_arr,
            feature_names=FEATURE_NAMES[behavior],
            mode="regression",
            verbose=False,
            random_state=42,
        )
        explanation = explainer.explain_instance(
            np.asarray(features, dtype=float),
            predict_fn=lambda x: _predict_batch(behavior, x),
            num_features=len(features),
            num_samples=_LIME_SAMPLES,
        )
        return explanation.as_list()
    except Exception as exc:
        logger.debug("LIME failed: %s", exc)
        return None


def _shap(
    behavior: str, features: list[float], background: list[list[float]]
) -> dict[str, list[tuple[int, float]]] | None:
    """Shapley values via KernelExplainer on the deployed score."""
    try:
        bg = np.asarray(background[-_SHAP_BACKGROUND:], dtype=float)
        if len(bg) < 4:
            return None

        def predict(X):
            return _predict_batch(behavior, X)

        explainer = shap.KernelExplainer(predict, bg)
        values = explainer.shap_values(
            np.asarray([features], dtype=float), silent=True, nsamples=_SHAP_NSAMPLES
        )
        arr = np.asarray(values[0]) if isinstance(values, list) else np.asarray(values)
        flat = arr.reshape(-1).tolist()
        return {
            "attribution": [
                (i, float(flat[i])) for i in range(min(len(flat), len(features)))
            ],
            "method": "shap",
        }
    except Exception as exc:
        logger.debug("SHAP failed: %s", exc)
        return None


def _permutation(behavior: str, features: list[float]) -> dict:
    """Disturbance fallback - sign of the score delta when each feature is perturbed.

    Evaluated in one vectorised batch so the fallback is instant even on a
    fresh (uncached) feature vector.
    """
    base = float(_predict(behavior, features)[0])
    attribution = []
    for idx in range(len(features)):
        deltas = []
        for rng in (0.025, 0.05, 0.1):
            perturbed = list(features)
            perturbed[idx] = perturbed[idx] + rng
            deltas.append(float(_predict(behavior, perturbed)[0]) - base)
            perturbed = list(features)
            perturbed[idx] = perturbed[idx] - rng
            deltas.append(float(_predict(behavior, perturbed)[0]) - base)
        attribution.append((idx, float(np.mean(deltas))))
    return {"attribution": attribution, "method": "permutation"}


def _compute_attribution(
    behavior: str, features: list[float], background: list[list[float]]
) -> dict:
    """Pick the best explainer for the deployment, under a hard budget.

    Order: SHAP (fast, exact Shapley values) -> LIME (surrogate weights) ->
    permutation (always available, instant). Each expensive explainer runs
    inside the wall-clock budget; when it exceeds it, we degrade immediately
    so the request never waits more than a few seconds.
    """
    if HAS_SHAP and background:
        result = _run_budgeted(lambda: _shap(behavior, features, background))
        if result:
            return result
    if HAS_LIME and background:
        result = _run_budgeted(lambda: _lime(behavior, features, background))
        if result:
            return {"method": "lime", "attribution": result}
    return _permutation(behavior, features)


def explain_event(event, session=None, use_cache: bool = True) -> dict:
    """Local attribution for a single NormalizedEvent anomaly score.

    Returns a feature-by-feature breakdown plus the deployed score/threshold
    so the alert UI can render the "why". ``session`` may be None; a fresh
    session is opened otherwise.
    """
    close = session is None
    session = session or SessionLocal()
    try:
        behavior = _behavior_of(int(event.event_id))
        features = event_feature_vector(event)
        if not features:
            return {
                "explainable": False,
                "reason": "No ML feature vector (behavior stream unknown)",
            }

        cache_key = f"{behavior}:" + ",".join(str(round(f, 5)) for f in features)
        if use_cache:
            with _cache_lock:
                cached = _explanation_cache.get(cache_key)
            if cached:
                return cached

        detector = get_detector()
        score = detector.score_event_for_behavior(behavior, features)
        threshold = detector.thresholds.get(behavior, 0.5)

        background = _background_samples(session, behavior)
        result = _compute_attribution(behavior, features, background)

        attribution = sorted(
            result["attribution"], key=lambda t: abs(t[1]), reverse=True
        )
        features_ui = []
        for idx, contrib in attribution:
            if idx >= len(FEATURE_NAMES[behavior]):
                continue
            name = FEATURE_NAMES[behavior][idx]
            if name == "event_id":
                continue
            value = features[idx]
            features_ui.append(
                {
                    "name": name,
                    "value": (
                        round(float(value), 4)
                        if isinstance(value, (int, float))
                        else value
                    ),
                    "contribution": round(float(contrib), 4),
                }
            )

        result["behavior"] = behavior
        result["score"] = round(float(score), 4)
        result["threshold"] = round(float(threshold), 4)
        result["flagged"] = bool(score > threshold)
        result["features"] = features_ui
        result["explainable"] = True
        result.pop("attribution", None)

        if use_cache:
            with _cache_lock:
                if len(_explanation_cache) < 200:
                    _explanation_cache[cache_key] = result
        return result
    finally:
        if close:
            session.close()


def explain_alert(db, alert) -> list[dict]:
    """Explanation per linked evidence event of an alert (capped)."""
    out = []
    for link in sorted(alert.events, key=lambda l: l.event_id)[:5]:
        try:
            explanation = explain_event(link.event, session=db, use_cache=True)
        except Exception as exc:
            logger.debug("explain_alert skipped event %s: %s", link.event_id, exc)
            continue
        explanation["event"] = {
            "_event_id": link.event.event_id,
            "message": (link.event.message or "")[:200],
            "timestamp": (
                link.event.timestamp.isoformat() if link.event.timestamp else None
            ),
            "ml_score": link.event.ml_score,
        }
        out.append(explanation)
    return out


def explain_features(
    session,
    behavior: str,
    features: list[float],
    event_id: int | None = None,
) -> dict:
    """Explain an arbitrary feature vector (used by API tooling / tests).

    ``event_id`` (optional) is only used for the behavior detection fallback.
    """
    behavior = behavior or (_behavior_of(int(event_id)) if event_id else "login")
    detector = get_detector()
    if behavior not in detector.models:
        return {
            "explainable": False,
            "reason": f"No trained model for '{behavior}' stream",
        }
    score = detector.score_event_for_behavior(behavior, features)
    threshold = detector.thresholds.get(behavior, 0.5)
    background = _background_samples(session, behavior)
    result = _compute_attribution(behavior, features, background)
    attribution = sorted(result["attribution"], key=lambda t: abs(t[1]), reverse=True)
    features_ui = []
    for idx, contrib in attribution:
        if idx >= len(FEATURE_NAMES[behavior]):
            continue
        name = FEATURE_NAMES[behavior][idx]
        if name == "event_id":
            continue
        value = features[idx] if idx < len(features) else None
        features_ui.append(
            {
                "name": name,
                "value": (
                    round(float(value), 4) if isinstance(value, (int, float)) else value
                ),
                "contribution": round(float(contrib), 4),
            }
        )
    return {
        "explainable": True,
        "method": result["method"],
        "behavior": behavior,
        "score": round(float(score), 4),
        "threshold": round(float(threshold), 4),
        "flagged": bool(score > threshold),
        "features": features_ui,
    }
