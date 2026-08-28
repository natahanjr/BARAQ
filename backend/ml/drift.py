"""Online-learning drift detection (roadmap 4.1).

Enhanced drift detection with:
1. Score-level PSI (existing) - compares model score distributions
2. Feature-level PSI (new) - detects drift in individual feature distributions
3. Concept drift detection - monitors relationship between features and labels
4. Automated drift response - triggers retraining with severity-based actions
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import numpy as np

from backend.config import ML_DRIFT_MIN_SAMPLES, ML_DRIFT_RATE, ML_PSI_WATCH
from backend.database.connection import SessionLocal
from backend.ml.anomaly import get_detector

logger = logging.getLogger("baraq.ml.drift")


def psi(reference: np.ndarray, current: np.ndarray, buckets: int = 10) -> float:
    """Population stability index between two score distributions.

    Buckets are built on the reference quantiles so both distributions are
    compared on the same boundaries. Returns 0 when identical; > 0.25 is
    conventionally "significant drift".
    """
    reference = np.asarray(reference, dtype=float).ravel()
    current = np.asarray(current, dtype=float).ravel()
    if len(reference) < 2 or len(current) < 2:
        return 0.0
    edges = np.quantile(reference, np.linspace(0.0, 1.0, buckets + 1)[1:-1])
    edges = np.unique(edges)
    if len(edges) < 1:
        return 0.0
    bounds = np.concatenate([[-np.inf], edges, [np.inf]])
    ref_hist, _ = np.histogram(reference, bins=bounds)
    cur_hist, _ = np.histogram(current, bins=bounds)
    ref_p = ref_hist / max(ref_hist.sum(), 1)
    cur_p = cur_hist / max(cur_hist.sum(), 1)
    # Zero-count cells get a floor so the log ratio stays finite.
    ref_p = np.clip(ref_p, 1e-6, None)
    cur_p = np.clip(cur_p, 1e-6, None)
    return float(np.sum((cur_p - ref_p) * np.log(cur_p / ref_p)))


def feature_psi(reference_features: np.ndarray, current_features: np.ndarray) -> List[float]:
    """Compute PSI for each feature independently.

    Returns list of PSI values, one per feature column.
    High PSI (>0.25) indicates significant drift in that feature.
    """
    # Ensure 2D arrays
    ref = np.atleast_2d(reference_features)
    cur = np.atleast_2d(current_features)
    if ref.shape[1] != cur.shape[1]:
        return []

    psi_values = []
    for col in range(ref.shape[1]):
        ref_col = ref[:, col]
        cur_col = cur[:, col]
        # Skip constant features
        if np.std(ref_col) < 1e-6 or np.std(cur_col) < 1e-6:
            psi_values.append(0.0)
            continue
        psi_values.append(psi(ref_col, cur_col))
    return psi_values


def _verdict(score: float) -> str:
    if score > ML_DRIFT_RATE:
        return "drift"
    if score > ML_PSI_WATCH:
        return "watch"
    return "ok"


def check_drift(session=None, hours: int = 12) -> dict:
    """Compare the last ``hours`` of features per stream to the baselines.

    Enhanced with feature-level drift detection and concept drift monitoring.
    Returns per-behavior PSI + verdict and an overall status.
    """
    detector = get_detector()
    if not detector.is_ready or not detector.baselines:
        return {"status": "not-trained", "streams": {}}

    close = session is None
    session = session or SessionLocal()
    try:
        from backend.ml.anomaly import (
            LOGIN_EVENTS,
            PROCESS_EVENTS,
            _load_behavior_features,
            _load_network_features,
        )

        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        streams: dict[str, dict] = {}

        # Store reference features for feature-level drift
        reference_features: Dict[str, np.ndarray] = {}

        for behavior, loader, events in (
            ("login", _load_behavior_features, LOGIN_EVENTS),
            ("process", _load_behavior_features, PROCESS_EVENTS),
        ):
            baseline = detector.baselines.get(behavior)
            if baseline is None or len(baseline) < 2:
                continue
            X, _ = loader(session, since, events, with_labels=True)
            if len(X) < ML_DRIFT_MIN_SAMPLES:
                continue

            # Score-level PSI
            scores = detector._rank_of(
                [float(detector._score_with(detector.models[behavior], row)) for row in X],
                baseline,
            )
            score_psi = psi(baseline, np.asarray(scores))

            # Feature-level PSI
            feature_psi_values = feature_psi(baseline, X) if len(X) > 10 else []
            feature_drift = [i for i, p in enumerate(feature_psi_values) if p > 0.25]

            streams[behavior] = {
                "psi": round(score_psi, 4),
                "verdict": _verdict(score_psi),
                "samples": int(len(X)),
                "window_hours": hours,
                "feature_drift_count": len(feature_drift),
                "feature_drifted_indices": feature_drift[:5],  # Top 5 drifted features
                "feature_psi_values": [round(p, 4) for p in feature_psi_values[:10]],  # Top 10
            }

        # Network stream
        net_baseline = detector.baselines.get("network")
        if net_baseline is not None and len(net_baseline) >= 2:
            net_X, _rows = _load_network_features(session, since)
            if len(net_X) >= ML_DRIFT_MIN_SAMPLES:
                model = detector.models.get("network")
                scores = detector._rank_of(
                    [float(detector._score_with(model, row)) for row in net_X],
                    net_baseline,
                )
                score_psi = psi(net_baseline, np.asarray(scores))

                # Feature-level PSI for network
                feature_psi_values = feature_psi(net_baseline, net_X) if len(net_X) > 10 else []
                feature_drift = [i for i, p in enumerate(feature_psi_values) if p > 0.25]

                streams["network"] = {
                    "psi": round(score_psi, 4),
                    "verdict": _verdict(score_psi),
                    "samples": int(len(net_X)),
                    "window_hours": hours,
                    "feature_drift_count": len(feature_drift),
                    "feature_drifted_indices": feature_drift[:5],
                    "feature_psi_values": [round(p, 4) for p in feature_psi_values[:10]],
                }

        # Overall status
        status = "drift" if any(s["verdict"] == "drift" for s in streams.values()) else (
            "watch" if any(s["verdict"] == "watch" for s in streams.values()) else "ok"
        )

        # Determine recommended action
        if status == "drift":
            action = "retrain_immediate"
        elif status == "watch":
            action = "retrain_scheduled"
        else:
            action = "none"

        report = {
            "status": status,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "streams": streams,
            "recommended_action": action,
            "note": "PSI > BARAQ_ML_DRIFT_RATE triggers scheduler retraining",
        }
        if status != "ok":
            logger.warning("ML drift: %s (%s)", status, {
                k: v["psi"] for k, v in streams.items()
            })
        return report
    finally:
        if close:
            session.close()


def check_concept_drift(session=None, hours: int = 24) -> dict:
    """Check for concept drift by monitoring label distribution changes.

    Concept drift occurs when the relationship between features and labels
    changes over time (e.g., new attack patterns that weren't in training).
    """
    detector = get_detector()
    if not detector.is_ready:
        return {"status": "not-trained"}

    close = session is None
    session = session or SessionLocal()
    try:
        from backend.ml.anomaly import _verdict_map
        from sqlalchemy import select
        from backend.database.models import NormalizedEvent

        since = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Get recent verdicts
        verdicts = _verdict_map(session)
        if not verdicts:
            return {"status": "no_verdicts", "samples": 0}

        # Count positive/negative labels
        recent_events = session.scalars(
            select(NormalizedEvent.id)
            .where(NormalizedEvent.timestamp >= since)
        ).all()

        labeled_ids = [eid for eid in recent_events if eid in verdicts]
        if len(labeled_ids) < 20:
            return {"status": "insufficient_data", "samples": len(labeled_ids)}

        positive_rate = sum(1 for eid in labeled_ids if verdicts[eid] == 1) / len(labeled_ids)

        # Compare with training distribution (approximate)
        # High positive rate in recent data suggests concept drift
        concept_drift = positive_rate > 0.3  # More than 30% positives is unusual

        return {
            "status": "concept_drift" if concept_drift else "ok",
            "recent_positive_rate": round(positive_rate, 4),
            "samples": len(labeled_ids),
            "window_hours": hours,
        }
    finally:
        if close:
            session.close()