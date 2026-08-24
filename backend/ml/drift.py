"""Online-learning drift detection (roadmap 4.1).

The detector is trained on a reference window; as the environment changes
(new software, new users, new attacker behaviour) the *current* feature
distribution drifts away from that baseline. ``psi`` implements the
population stability index; ``check_drift`` compares recent features per
behaviour stream against the detector's stored baselines and returns a
verdict (``ok`` / ``watch`` / ``drift``) the scheduler uses to trigger
incremental retraining.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

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


def _verdict(score: float) -> str:
    if score > ML_DRIFT_RATE:
        return "drift"
    if score > ML_PSI_WATCH:
        return "watch"
    return "ok"


def check_drift(session=None, hours: int = 12) -> dict:
    """Compare the last ``hours`` of features per stream to the baselines.

    Returns per-behavior PSI + verdict and an overall status. The detector
    must be ready (trained) or the report is ``{"status": "not-trained"}``.
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
            scores = detector._rank_of(
                [float(detector._score_with(detector.models[behavior], row)) for row in X],
                baseline,
            )
            score = psi(baseline, np.asarray(scores))
            streams[behavior] = {
                "psi": round(score, 4),
                "verdict": _verdict(score),
                "samples": int(len(X)),
                "window_hours": hours,
            }

        net_baseline = detector.baselines.get("network")
        if net_baseline is not None and len(net_baseline) >= 2:
            net_X, _rows = _load_network_features(session, since)
            if len(net_X) >= ML_DRIFT_MIN_SAMPLES:
                model = detector.models.get("network")
                scores = detector._rank_of(
                    [float(detector._score_with(model, row)) for row in net_X],
                    net_baseline,
                )
                score = psi(net_baseline, np.asarray(scores))
                streams["network"] = {
                    "psi": round(score, 4),
                    "verdict": _verdict(score),
                    "samples": int(len(net_X)),
                    "window_hours": hours,
                }

        status = "drift" if any(s["verdict"] == "drift" for s in streams.values()) else (
            "watch" if any(s["verdict"] == "watch" for s in streams.values()) else "ok"
        )
        report = {
            "status": status,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "streams": streams,
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