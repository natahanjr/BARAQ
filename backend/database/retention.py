"""Automated data retention - prune telemetry older than the configured window.

The scheduler calls :func:`purge_old_data` on a regular cadence so the
database never grows unbounded. Child rows (alert events / notes / actions)
are removed by the database-level ``ondelete=CASCADE`` foreign keys.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.config import EVENT_RETENTION_DAYS
from backend.database.models import (
    Alert,
    DashboardSnapshot,
    DnsQuery,
    EmailMessage,
    FileScan,
    HttpRequest,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    ThreatIntelRecord,
    UsbDevice,
    VulnFinding,
)

logger = logging.getLogger("baraq.db")

#: (model, timestamp column) for every telemetry/history table with a time column.
#: Chat history, audit logs, reports and users are operator data and are kept.
_PURGE_TARGETS: list[tuple] = [
    (NormalizedEvent, NormalizedEvent.timestamp),
    (ProcessRecord, ProcessRecord.observed_at),
    (NetworkConnection, NetworkConnection.observed_at),
    (DnsQuery, DnsQuery.observed_at),
    (HttpRequest, HttpRequest.observed_at),
    (EmailMessage, EmailMessage.received_at),
    (UsbDevice, UsbDevice.inserted_at),
    (FileScan, FileScan.scanned_at),
    (VulnFinding, VulnFinding.found_at),
    (DashboardSnapshot, DashboardSnapshot.timestamp),
    (Alert, Alert.created_at),
    # Stale cached intel verdicts age out with telemetry; fresh lookups re-populate.
    (ThreatIntelRecord, ThreatIntelRecord.checked_at),
]


def purge_old_data(
    session: Session, days: int = EVENT_RETENTION_DAYS
) -> dict[str, int]:
    """Delete every record older than ``days`` (default config value).

    Returns a map of ``{table_name: deleted_rows}``. Safe to run repeatedly;
    nothing is deleted when there is nothing old.
    """
    cutoff = datetime.now(UTC) - timedelta(days=days)
    purged: dict[str, int] = {}
    for model, column in _PURGE_TARGETS:
        purged[model.__tablename__] = int(
            session.execute(delete(model).where(column < cutoff)).rowcount or 0
        )
    session.commit()
    total = sum(purged.values())
    if total:
        logger.info("Retention purge (older than %dd): %s", days, purged)
    return purged
