"""Incremental detection cursor.

Persists the id of the last normalised event that has already been fed
through the detection pipeline. On every run the rules engine starts from
this cursor instead of re-scanning the whole detection window, which makes
detection work proportional to the *incoming* event rate rather than to the
accumulated window size.

The cursor is process-global (single-writer): ``run_pipeline`` advances it
under ``CURSOR_LOCK`` after a detection pass, so concurrent ingest handlers
and the background scheduler never evaluate the same event range twice.
"""

from __future__ import annotations

import threading

from sqlalchemy import func, select

from backend.database.models import NormalizedEvent, SystemState

#: Key under which the last-evaluated event id is stored in ``system_state``.
CURSOR_KEY = "detection_cursor"

#: Serialises cursor read -> detection -> cursor advance in one process.
CURSOR_LOCK = threading.Lock()


def get_cursor(session) -> int:
    """Last event id already evaluated (0 = nothing evaluated yet)."""
    row = session.get(SystemState, CURSOR_KEY)
    if row is None or not row.value:
        return 0
    try:
        return int(row.value)
    except ValueError:
        return 0


def set_cursor(session, value: int) -> None:
    """Advance the cursor; the caller commits."""
    row = session.get(SystemState, CURSOR_KEY)
    if row is None:
        session.add(SystemState(key=CURSOR_KEY, value=str(value)))
    else:
        row.value = str(value)


def max_event_id(session) -> int:
    """Highest persisted normalised event id (0 on an empty events table)."""
    return session.scalar(select(func.max(NormalizedEvent.id))) or 0
