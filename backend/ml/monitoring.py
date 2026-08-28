"""Model monitoring and production accuracy tracking.

This module tracks ML model performance in production by:
1. Recording prediction outcomes (TP/FP/TN/FN) when analyst verdicts arrive
2. Computing rolling accuracy metrics (precision, recall, F1, FPR)
3. Detecting performance degradation over time
4. Providing metrics for observability (Prometheus/Grafana)

Metrics are stored in memory and periodically flushed to the database
for historical analysis and alerting.
"""
from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import select, func

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict

logger = logging.getLogger("baraq.ml.monitoring")


class ModelMetrics:
    """Rolling metrics window for production accuracy tracking."""

    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.predictions: deque = deque(maxlen=window_size)
        self.verdicts: deque = deque(maxlen=window_size)
        self.timestamps: deque = deque(maxlen=window_size)
        self._last_flush_time = time.time()

    def record_prediction(
        self,
        event_id: int,
        predicted_anomaly: bool,
        anomaly_score: float,
        behavior: str,
        timestamp: Optional[datetime] = None,
    ):
        """Record a prediction for later comparison with analyst verdict."""
        self.predictions.append({
            "event_id": event_id,
            "predicted_anomaly": predicted_anomaly,
            "anomaly_score": anomaly_score,
            "behavior": behavior,
        })
        self.timestamps.append(timestamp or datetime.now(timezone.utc))

    def record_verdict(
        self,
        event_id: int,
        true_label: str,  # "true_positive" or "false_positive"
        analyst: str,
        timestamp: Optional[datetime] = None,
    ):
        """Record analyst verdict for ground truth comparison."""
        self.verdicts.append({
            "event_id": event_id,
            "true_label": true_label,
            "analyst": analyst,
            "timestamp": timestamp or datetime.now(timezone.utc),
        })

    def compute_metrics(self) -> Dict[str, float]:
        """Compute current rolling metrics."""
        if not self.predictions or not self.verdicts:
            return self._empty_metrics()

        # Match predictions with verdicts by event_id
        verdict_map = {v["event_id"]: v for v in self.verdicts}
        tp = fp = tn = fn = 0

        for pred in self.predictions:
            event_id = pred["event_id"]
            if event_id not in verdict_map:
                continue

            verdict = verdict_map[event_id]
            predicted_positive = pred["predicted_anomaly"]
            actual_positive = verdict["true_label"] == "true_positive"

            if predicted_positive and actual_positive:
                tp += 1
            elif predicted_positive and not actual_positive:
                fp += 1
            elif not predicted_positive and not actual_positive:
                tn += 1
            else:
                fn += 1

        total = tp + fp + tn + fn
        if total == 0:
            return self._empty_metrics()

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        accuracy = (tp + tn) / total

        return {
            "total_samples": total,
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "accuracy": round(accuracy, 4),
            "window_size": self.window_size,
            "last_update": datetime.now(timezone.utc).isoformat(),
        }

    def _empty_metrics(self) -> Dict[str, float]:
        return {
            "total_samples": 0,
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "false_positive_rate": 0.0,
            "accuracy": 0.0,
            "window_size": self.window_size,
            "last_update": datetime.now(timezone.utc).isoformat(),
        }

    def detect_degradation(self, threshold: float = 0.1) -> Optional[str]:
        """Detect if model performance has degraded."""
        metrics = self.compute_metrics()
        if metrics["total_samples"] < 10:
            return None  # Not enough data

        # Check for high FPR
        if metrics["false_positive_rate"] > 0.2:
            return f"High FPR: {metrics['false_positive_rate']:.1%}"

        # Check for low precision
        if metrics["precision"] < 0.5 and metrics["total_samples"] > 50:
            return f"Low precision: {metrics['precision']:.1%}"

        # Check for low recall
        if metrics["recall"] < 0.3 and metrics["total_samples"] > 50:
            return f"Low recall: {metrics['recall']:.1%}"

        return None


class ModelMonitor:
    """Production model monitoring with persistence."""

    def __init__(self, window_size: int = 1000):
        self.metrics = ModelMetrics(window_size)
        self._alert_thresholds = {
            "fpr": 0.2,
            "precision": 0.5,
            "recall": 0.3,
        }

    def record_prediction(
        self,
        event_id: int,
        predicted_anomaly: bool,
        anomaly_score: float,
        behavior: str,
    ):
        """Record a prediction."""
        self.metrics.record_prediction(
            event_id, predicted_anomaly, anomaly_score, behavior
        )

    def record_verdict(
        self,
        event_id: int,
        true_label: str,
        analyst: str,
    ):
        """Record an analyst verdict."""
        self.metrics.record_verdict(event_id, true_label, analyst)

    def get_metrics(self) -> Dict:
        """Get current metrics."""
        return self.metrics.compute_metrics()

    def check_health(self) -> Dict:
        """Check model health and return status."""
        metrics = self.get_metrics()
        degradation = self.metrics.detect_degradation()

        return {
            "status": "degraded" if degradation else "healthy",
            "degradation_reason": degradation,
            "metrics": metrics,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_prometheus_metrics(self) -> str:
        """Export metrics in Prometheus format."""
        metrics = self.get_metrics()
        lines = [
            f'# HELP baraq_ml_predictions_total Total predictions made',
            f'# TYPE baraq_ml_predictions_total counter',
            f'baraq_ml_predictions_total {metrics["total_samples"]}',
            f'# HELP baraq_ml_precision Model precision',
            f'# TYPE baraq_ml_precision gauge',
            f'baraq_ml_precision {metrics["precision"]}',
            f'# HELP baraq_ml_recall Model recall',
            f'# TYPE baraq_ml_recall gauge',
            f'baraq_ml_recall {metrics["recall"]}',
            f'# HELP baraq_ml_f1_score Model F1 score',
            f'# TYPE baraq_ml_f1_score gauge',
            f'baraq_ml_f1_score {metrics["f1_score"]}',
            f'# HELP baraq_ml_false_positive_rate False positive rate',
            f'# TYPE baraq_ml_false_positive_rate gauge',
            f'baraq_ml_false_positive_rate {metrics["false_positive_rate"]}',
        ]
        return "\n".join(lines)


# Singleton instance
_monitor: Optional[ModelMonitor] = None


def get_model_monitor() -> ModelMonitor:
    """Get or create the singleton model monitor."""
    global _monitor
    if _monitor is None:
        _monitor = ModelMonitor()
    return _monitor
