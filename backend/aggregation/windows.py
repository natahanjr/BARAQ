"""Phase 4 aggregation windows (spec 4.13, 4.14).

Every aggregation policy carries a bounded, configurable window per
behavior family - never hardcoded in the grouping engine. A sliding window
is used: an alert joins a live group only when it lands within the family
window of the group's last_seen. 10:00 + 10:10 + 10:20 with a 30-minute
window can be one group; 10:00 + 11:30 never stays in the same group.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from .grouping import window_minutes


def window_for(family: str) -> timedelta:
    return timedelta(minutes=window_minutes(family))


def within_window(last_seen: datetime, alert_time: datetime, family: str) -> bool:
    return alert_time <= last_seen + window_for(family)


def quiet_cutoff(last_seen: datetime, now: datetime, quiet_after_minutes: int) -> bool:
    return now > last_seen + timedelta(minutes=quiet_after_minutes)


def close_cutoff(last_seen: datetime, now: datetime, close_after_minutes: int) -> bool:
    return now > last_seen + timedelta(minutes=close_after_minutes)
