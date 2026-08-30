"""Dataset collector - consumes the existing BARAQ telemetry pipeline.

Every sweep cycle the collector picks up the newest ``NormalizedEvent``
rows (cursor = last collected source event id), converts each into the
compact research representation, deduplicates via deterministic
fingerprint + unique constraints, resolves alert/incident/label metadata
in batch, and updates the collection's running total.

The collector is a consumer of the existing pipeline - it never touches
telemetry ingestion itself, so normal SOC operations are unaffected.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import bindparam, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from backend.config import DATASET_COLLECT_BATCH, DATASET_COLLECTOR_VERSION
from backend.database.models import (
    Alert,
    AlertEventLink,
    AlertVerdict,
    DatasetCollection,
    DatasetEvent,
    EntityRisk,
    IncidentAlertLink,
    NormalizedEvent,
)

from .anonymize import Pseudonymizer
from .normalize import to_dataset_row

log = logging.getLogger("dataset.collector")


def active_collection(
    session: Session, create_if_missing: bool = True
) -> DatasetCollection | None:
    """The current (active or paused) collection; creates the default one."""
    from backend.config import (
        DATASET_ANONYMIZE,
        DATASET_ENABLED,
        DATASET_EVENTS_PER_FILE,
        DATASET_EXPORT_INTERVAL_HOURS,
        DATASET_FORMAT,
        DATASET_INCLUDE_LABELS,
        DATASET_NAME,
        DATASET_TARGET_EVENTS,
    )

    coll = (
        session.execute(
            select(DatasetCollection)
            .where(DatasetCollection.status.in_(["active", "paused"]))
            .order_by(DatasetCollection.id.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    if coll is not None:
        return coll
    if not create_if_missing or not DATASET_ENABLED:
        return None
    coll = DatasetCollection(
        name=DATASET_NAME,
        status="active",
        target_events=DATASET_TARGET_EVENTS,
        events_per_file=DATASET_EVENTS_PER_FILE,
        export_interval_hours=DATASET_EXPORT_INTERVAL_HOURS,
        format=DATASET_FORMAT,
        anonymize=DATASET_ANONYMIZE,
        include_labels=DATASET_INCLUDE_LABELS,
        total_events=0,
        parts=0,
    )
    session.add(coll)
    session.flush()
    log.info(
        "Dataset collection '%s' created (target=%d)", coll.name, coll.target_events
    )
    return coll


def _last_source_event_id(session: Session, collection_id: int) -> int:
    row = session.execute(
        select(func.max(DatasetEvent.source_event_id)).where(
            DatasetEvent.collection_id == collection_id
        )
    ).scalar()
    return int(row or 0)


def _resolve_labels(session: Session, event_ids: list[int]) -> dict[int, dict]:
    """Batch-resolve alert/incident/verdict metadata for a set of events."""
    if not event_ids:
        return {}
    labels: dict[int, dict] = {}
    links = (
        session.execute(
            select(AlertEventLink)
            .where(AlertEventLink.event_id.in_(event_ids))
            .limit(5000)
        )
        .scalars()
        .all()
    )
    alert_ids = [l.alert_id for l in links]
    if not alert_ids:
        return labels

    alerts = {
        a.id: a
        for a in session.execute(select(Alert).where(Alert.id.in_(alert_ids)))
        .scalars()
        .all()
    }
    verdicts = {
        v.alert_id: v.verdict
        for v in session.execute(
            select(AlertVerdict).where(AlertVerdict.alert_id.in_(alert_ids))
        )
        .scalars()
        .all()
    }
    incident_map: dict[int, int] = {}
    inc_links = (
        session.execute(
            select(IncidentAlertLink).where(IncidentAlertLink.alert_id.in_(alert_ids))
        )
        .scalars()
        .all()
    )
    for il in inc_links:
        incident_map.setdefault(il.alert_id, il.incident_id)

    for link in links:
        alert = alerts.get(link.alert_id)
        if not alert:
            continue
        entry = labels.setdefault(
            link.event_id,
            {
                "rule": "",
                "mitre": "",
                "alert_id": None,
                "incident_id": None,
                "label": "",
            },
        )
        if not entry["rule"]:
            entry["rule"] = alert.rule or ""
        if not entry["mitre"]:
            entry["mitre"] = alert.mitre_id or ""
        if entry["alert_id"] is None:
            entry["alert_id"] = alert.id
        if entry["incident_id"] is None and incident_map.get(alert.id):
            entry["incident_id"] = incident_map[alert.id]
        if not entry["label"] and verdicts.get(alert.id):
            entry["label"] = verdicts[alert.id]
    return labels


def _resolve_entity_risk(session: Session, names: set[str]) -> dict[str, float]:
    """Batch-load entity risk scores for users/hosts."""
    if not names:
        return {}
    rows = session.execute(
        select(EntityRisk.entity_kind, EntityRisk.entity_name, EntityRisk.score).where(
            EntityRisk.entity_name.in_(list(names)), EntityRisk.score.isnot(None)
        )
    ).all()
    best: dict[str, float] = {}
    for kind, name, score in rows:
        best[name] = max(best.get(name, 0.0), float(score or 0.0))
    return best


def sweep(
    session: Session, limit: int | None = None, collection_id: int | None = None
) -> dict:
    """Collect the next batch of uncollected telemetry events.

    Returns counts ``{collected, deduplicated, total, target_reached}``.
    Safe to call concurrently: uniqueness constraints make double-sweeps
    no-ops for already-inserted events.
    """
    limit = limit or DATASET_COLLECT_BATCH
    coll = (
        session.execute(
            select(DatasetCollection).order_by(DatasetCollection.id.desc()).limit(1)
        ).scalar_one_or_none()
        if collection_id is None
        else session.get(DatasetCollection, collection_id)
    )
    if coll is None:
        coll = active_collection(session, create_if_missing=True)
    if coll is None:
        return {
            "collected": 0,
            "deduplicated": 0,
            "total": 0,
            "target_reached": False,
            "collection_id": None,
        }
    if coll.status != "active":
        return {
            "collected": 0,
            "deduplicated": 0,
            "total": coll.total_events,
            "target_reached": coll.status == "complete",
            "collection_id": coll.id,
        }

    if coll.total_events >= coll.target_events:
        coll.status = "complete"
        coll.completed_at = coll.completed_at or datetime.now(UTC)
        session.commit()
        return {
            "collected": 0,
            "deduplicated": 0,
            "total": coll.total_events,
            "target_reached": True,
            "collection_id": coll.id,
        }

    cursor = _last_source_event_id(session, coll.id)
    events = (
        session.execute(
            select(NormalizedEvent)
            .where(NormalizedEvent.id > cursor, NormalizedEvent.demo == False)
            .order_by(NormalizedEvent.id.asc())
            .limit(limit)
        )
        .scalars()
        .all()
    )
    if not events:
        return {
            "collected": 0,
            "deduplicated": 0,
            "total": coll.total_events,
            "target_reached": False,
            "collection_id": coll.id,
        }

    anonymizer = Pseudonymizer(coll.id, coll.anonymize)
    labels = _resolve_labels(session, [e.id for e in events])
    names = {e.user for e in events if e.user} | {e.host for e in events if e.host}
    risk_map = _resolve_entity_risk(session, names)

    stmt = (
        insert(DatasetEvent)
        .values(
            collection_id=coll.id,
            event_fingerprint=bindparam("event_fingerprint"),
            source_event_id=bindparam("source_event_id"),
            timestamp=bindparam("timestamp"),
            event_type=bindparam("event_type"),
            event_source=bindparam("event_source"),
            payload_normalized=bindparam("payload_normalized"),
            exported=False,
        )
        .on_conflict_do_nothing(index_elements=["collection_id", "event_fingerprint"])
    )

    values = []
    for ev in events:
        fingerprint, row = to_dataset_row(
            ev,
            labels,
            risk_map,
            anonymizer,
            coll.include_labels,
            DATASET_COLLECTOR_VERSION,
        )
        values.append(
            {
                "event_fingerprint": fingerprint,
                "source_event_id": ev.id,
                "timestamp": ev.timestamp,
                "event_type": row["event_type"],
                "event_source": row["event_source"],
                "payload_normalized": row["_payload"],
            }
        )
    if values:
        session.execute(stmt, values)

    pre_total = coll.total_events
    total = (
        session.execute(
            select(func.count(DatasetEvent.id)).where(
                DatasetEvent.collection_id == coll.id
            )
        ).scalar()
        or 0
    )
    coll.total_events = int(total)
    coll.updated_at = datetime.now(UTC)
    if int(total) >= coll.target_events:
        coll.status = "complete"
        coll.completed_at = coll.completed_at or datetime.now(UTC)
    session.commit()

    inserted = max(0, int(total) - pre_total)
    return {
        "collected": len(events),
        "deduplicated": max(0, len(events) - inserted),
        "total": int(total),
        "target_reached": coll.status == "complete",
        "collection_id": coll.id,
    }
