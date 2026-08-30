"""Alert deduplication (spec 3.8-3.10).

Repeated detections with the same fingerprint merge into ONE alert within
the detector's configurable window (spec 3.9). Merging is only allowed
while the existing alert is still active (OPEN/ACKNOWLEDGED/IN_PROGRESS)
and its last_seen is inside the window - an expired, resolved or closed
alert never absorbs unrelated future behavior (spec 3.10).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.alerting.models import AlertRecord
from backend.config import (
    ALERT_DEDUP_WINDOW_DEFAULT_MINUTES,
    ALERT_DEDUP_WINDOW_MINUTES,
)

_MERGEABLE_STATUSES = ("OPEN", "ACKNOWLEDGED", "IN_PROGRESS")


def window_minutes(detector_id: str) -> int:
    return ALERT_DEDUP_WINDOW_MINUTES.get(
        detector_id, ALERT_DEDUP_WINDOW_DEFAULT_MINUTES
    )


def find_existing(
    db: Session,
    fingerprint: str,
    detector_id: str,
    detection_time: datetime,
    now: datetime | None = None,
) -> AlertRecord | None:
    """The alert this detection should merge into, or None.

    Merging requires an exact fingerprint match AND an active status AND a
    last_seen inside the detector's dedup window.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(minutes=window_minutes(detector_id))
    stmt = (
        select(AlertRecord)
        .where(
            AlertRecord.alert_fingerprint == fingerprint,
            AlertRecord.status.in_(_MERGEABLE_STATUSES),
            AlertRecord.last_seen >= cutoff,
        )
        .order_by(AlertRecord.last_seen.desc(), AlertRecord.id.desc())
    )
    rows = list(db.scalars(stmt).all())
    if rows:
        return rows[0]
    return None


def merge(db: Session, alert: AlertRecord, detection_time: datetime) -> AlertRecord:
    """Merge one occurrence into an existing alert (spec 3.8, 3.44)."""
    alert.occurrence_count += 1
    alert.last_seen = max(alert.last_seen, detection_time)
    detection_ids = list(alert.detection_ids or [])
    alert.detection_ids = detection_ids
    alert.updated_at = datetime.now(UTC)
    return alert
