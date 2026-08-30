"""Data-quality tracking for the event pipeline (auto-fix corrupted data).

A process-wide tracker keeps a sliding window of validation outcomes per
channel/source, computes the corruption rate and maps it to a health status
(HEALTHY / WARNING / DEGRADED / CRITICAL).  The background monitor
(``backend/monitor/data_quality.py``) persists periodic snapshots to the
``data_quality_snapshots`` table for the history endpoint and triggers the
repair engine when the rate crosses the CRITICAL threshold.
"""

from __future__ import annotations

import threading
import time
from collections import Counter

from backend.config import (
    DATA_QUALITY_CRITICAL_RATE,
    DATA_QUALITY_DEGRADED_RATE,
    DATA_QUALITY_WARN_RATE,
    DATA_QUALITY_WINDOW_MINUTES,
)

_Entry = tuple[float, str, bool, str]  # (wallclock, channel, valid, reason)


def status_for_rate(rate: float) -> str:
    """Map a corruption rate (0..1) to a health status."""
    if rate >= DATA_QUALITY_CRITICAL_RATE:
        return "critical"
    if rate >= DATA_QUALITY_DEGRADED_RATE:
        return "degraded"
    if rate >= DATA_QUALITY_WARN_RATE:
        return "warning"
    return "healthy"


class QualityTracker:
    """Thread-safe sliding window of validation outcomes."""

    def __init__(self, window_minutes: int | None = None):
        self.window_minutes = window_minutes or DATA_QUALITY_WINDOW_MINUTES
        self._entries: list[_Entry] = []
        self._lock = threading.Lock()

    def record(self, channel: str, ok: bool, reason: str = "") -> None:
        """Record one validation outcome for a channel/source."""
        with self._lock:
            self._entries.append(
                (time.time(), channel or "unknown", bool(ok), reason[:200])
            )
            cutoff = time.time() - self.window_minutes * 60
            self._entries = [e for e in self._entries if e[0] >= cutoff]

    def _window(self, minutes: int | None) -> list[_Entry]:
        cutoff = time.time() - (minutes or self.window_minutes) * 60
        with self._lock:
            return [e for e in self._entries if e[0] >= cutoff]

    def window_rate(self, minutes: int | None = None) -> float:
        """Corruption ratio over the window; 0.0 when no samples."""
        window = self._window(minutes)
        if not window:
            return 0.0
        corrupted = sum(1 for _, _, ok, _ in window if not ok)
        return corrupted / len(window)

    def summary(self, minutes: int | None = None) -> dict:
        """Live snapshot: totals, per-channel split, rate, status, reasons."""
        window = self._window(minutes)
        total = len(window)
        valid = sum(1 for _, _, ok, _ in window if ok)
        corrupted = total - valid
        rate = corrupted / total if total else 0.0
        reasons: Counter[str] = Counter()
        per_channel: dict[str, dict] = {}
        for _, channel, ok, reason in window:
            entry = per_channel.setdefault(
                channel,
                {"total": 0, "valid": 0, "corrupted": 0, "corruption_rate": 0.0},
            )
            entry["total"] += 1
            if ok:
                entry["valid"] += 1
            else:
                entry["corrupted"] += 1
                if reason:
                    reasons[reason] += 1
        for entry in per_channel.values():
            entry["corruption_rate"] = (
                round(entry["corrupted"] / entry["total"], 4) if entry["total"] else 0.0
            )
        return {
            "window_minutes": minutes or self.window_minutes,
            "total": total,
            "valid": valid,
            "corrupted": corrupted,
            "corruption_rate": round(rate, 4),
            "status": status_for_rate(rate),
            "channels": per_channel,
            "reasons": dict(reasons.most_common(10)),
        }

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()


quality = QualityTracker()


def record_outcome(channel: str, ok: bool, reason: str = "") -> None:
    """Module-level shorthand used by the pipeline and collectors."""
    quality.record(channel, ok, reason)


def persist_snapshot(db) -> dict:
    """Write one DataQualitySnapshot row for the current window; returns it."""
    from backend.database.models import DataQualitySnapshot

    snapshot = quality.summary()
    row = DataQualitySnapshot(
        total=snapshot["total"],
        valid=snapshot["valid"],
        corrupted=snapshot["corrupted"],
        corruption_rate=snapshot["corruption_rate"],
        status=snapshot["status"],
        reasons=snapshot["reasons"],
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row.to_dict()


def snapshot_history(db, limit: int = 50) -> list[dict]:
    """Most recent persisted snapshots (oldest first) for the history API."""
    from sqlalchemy import select

    from backend.database.models import DataQualitySnapshot

    rows = db.scalars(
        select(DataQualitySnapshot).order_by(DataQualitySnapshot.id.desc()).limit(limit)
    ).all()
    return [r.to_dict() for r in reversed(rows)]
