"""v2 telemetry ingestion pipeline (Phase 1).

``ingest`` takes raw records and produces deduplicated, normalized,
enriched, persisted EVENTS.

Contract:
    raw records -> normalize -> enrich -> fingerprint dedup -> store

* Idempotent: replaying the same raw records is a no-op (unique fingerprint).
* Never alerts, never mutates risk, never opens incidents.
* The DB session is injected; the pipeline does not own connections.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from backend import config
from backend.telemetry.contract import EVENT
from backend.telemetry.enrichment.base import enrich
from backend.telemetry.models import TelemetryEvent
from backend.telemetry.normalization.base import normalize as _normalize

logger = logging.getLogger("baraq.telemetry.ingestion")


def normalize(raw: dict[str, Any], fallback_ts: datetime | None = None) -> EVENT | None:
    """Public alias - raw record -> EVENT (normalization boundary)."""
    return _normalize(raw, fallback_ts)


def _ensure_not_production_db() -> None:
    """Phase 0.7 isolation: refuse to write v2 telemetry into the v1
    production database, regardless of environment flags."""
    if (
        not config.V2_ENGINES_ALLOW_PROD
        and make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME
    ):
        raise RuntimeError(
            f"refusing: v2 telemetry ingestion is read-only against the "
            f"production database '{config.PRODUCTION_DB_NAME}'"
        )


def ingest(
    db: Session,
    raw_records: list[dict[str, Any]],
    *,
    enrich_enabled: bool = True,
) -> dict[str, int]:
    """Persist a batch of raw records, deduplicated by EVENT fingerprint.

    Returns stats: ``{"ingested": n, "duplicates": n, "normalized": n,
    "skipped": n, "failed": n}``. Never raises; a bad record is counted as
    failed/skipped and dropped. Refuses to run against the production DB.
    """
    stats = {
        "ingested": 0,
        "duplicates": 0,
        "normalized": 0,
        "skipped": 0,
        "failed": 0,
    }
    if not raw_records:
        return stats
    _ensure_not_production_db()

    # One fallback timestamp per batch keeps fingerprints deterministic so
    # replaying the same records is always a no-op.
    fallback_ts = datetime.now(UTC)

    events: list[EVENT] = []
    for raw in raw_records:
        try:
            event = _normalize(raw, fallback_ts)
        except Exception as exc:
            stats["failed"] += 1
            logger.warning("Normalization failed for record: %s", exc)
            continue
        if event is None:
            stats["skipped"] += 1
            continue
        if enrich_enabled:
            event = enrich(event, db)
        events.append(event)

    stats["normalized"] = len(events)
    if not events:
        return stats

    fingerprints = [e.fingerprint() for e in events]
    existing = set(
        db.scalars(
            select(TelemetryEvent.fingerprint).where(
                TelemetryEvent.fingerprint.in_(fingerprints)
            )
        ).all()
    )

    fresh: list[TelemetryEvent] = []
    for event in events:
        if event.fingerprint() in existing:
            stats["duplicates"] += 1
            continue
        existing.add(event.fingerprint())
        fresh.append(
            TelemetryEvent(
                fingerprint=event.fingerprint(),
                timestamp=event.timestamp,
                host=event.host,
                user=event.user,
                source=event.source,
                action=event.action,
                facts=event.facts,
                org=event.org,
                integrity=event.integrity,
                raw_json=event.raw if isinstance(event.raw, dict) else None,
                event_id=event.event_id,
                event_type=event.event_type,
                destination=event.destination,
                process=event.process,
                network=event.network,
                outcome=event.outcome,
                schema_version=event.schema_version,
            )
        )
    if fresh:
        db.add_all(fresh)
        db.commit()
    stats["ingested"] = len(fresh)
    return stats
