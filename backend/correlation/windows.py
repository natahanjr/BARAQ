"""Phase 5 correlation windows (spec 5.9, 5.10).

Every correlation rule carries a bounded, configurable window - never
hardcoded. A pair of groups only correlates when they fall inside the
sequence window, and a finding chain only stays a single chain while every
consecutive member pair is inside its window.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from backend import config


def window_minutes(window_key: str) -> int:
    return config.CORRELATION_WINDOWS_MINUTES.get(
        window_key, config.CORRELATION_WINDOW_DEFAULT_MINUTES
    )


def window_for(window_key: str) -> timedelta:
    return timedelta(minutes=window_minutes(window_key))


def within_window(
    earlier_time,
    later_time,
    window_key: str,
    *,
    clock_drift_seconds: int = 60,
) -> bool:
    """Consecutive-pair window check (spec 5.10): ``later - earlier`` must
    fit in the rule window, allowing a small bounded clock-drift slack."""
    delta = later_time - earlier_time
    if delta < timedelta(0):
        return True
    return delta <= window_for(window_key) + timedelta(seconds=clock_drift_seconds)


def quiet_cutoff(last_seen: datetime, now: datetime, quiet_after_minutes: int) -> bool:
    return now > last_seen + timedelta(minutes=quiet_after_minutes)


def close_cutoff(last_seen: datetime, now: datetime, close_after_minutes: int) -> bool:
    return now > last_seen + timedelta(minutes=close_after_minutes)
