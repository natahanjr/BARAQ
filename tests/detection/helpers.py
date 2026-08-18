"""Shared helpers for Phase 2 detection tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.telemetry.contract import EVENT


def dt(minutes_ago: float = 0) -> datetime:
    """Deterministic anchor timestamps: 2026-08-17 12:00:00 UTC minus offset."""
    return datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc) - timedelta(minutes=minutes_ago)


def event(**overrides) -> EVENT:
    """Canonical EVENT factory for tests. Every call is a distinct event."""
    base = {
        "timestamp": dt(),
        "host": "workstation-42",
        "user": "alice",
        "source": "test-source",
        "action": "-",
        "facts": {},
        "event_type": "",
        "process": {},
        "network": {},
    }
    base.update(overrides)
    return EVENT(**base)


def logon_failed(minutes_ago: float, user: str = "alice", host: str = "workstation-42",
                 source_ip: str = "198.51.100.7", **facts) -> EVENT:
    return event(
        timestamp=dt(minutes_ago),
        host=host,
        user=user,
        action="logon_failed",
        event_type="authentication",
        network={"src_ip": source_ip},
        facts={"source_ip": source_ip, **facts},
    )


def logon_success(minutes_ago: float, user: str = "alice", host: str = "workstation-42",
                  source_ip: str = "198.51.100.7", logon_type: int = 2) -> EVENT:
    return event(
        timestamp=dt(minutes_ago),
        host=host,
        user=user,
        action="logon",
        event_type="authentication",
        network={"src_ip": source_ip},
        facts={"source_ip": source_ip, "logon_type": logon_type},
    )


def file_modify(minutes_ago: float, host: str = "workstation-42", path: str = "C:\\data\\docs",
                process: str = "chrome.exe") -> EVENT:
    return event(
        timestamp=dt(minutes_ago),
        host=host,
        action="file_modify",
        event_type="file",
        process={"name": process},
        facts={"path": path},
    )


def shadow_delete(minutes_ago: float, host: str = "workstation-42") -> EVENT:
    return event(
        timestamp=dt(minutes_ago),
        host=host,
        action="shadow_delete",
        event_type="file",
        process={"name": "vssadmin.exe", "command_line": "vssadmin delete shadows /all /quiet"},
        facts={"command_line": "vssadmin delete shadows /all /quiet"},
    )


def seed_events(db, events: list[EVENT]) -> None:
    """Persist normalized EVENTs into v2_events (as the pipeline would).

    Re-seeding overlapping events is a no-op by design (fingerprint dedup).
    """
    from backend.telemetry.ingestion.pipeline import ingest

    raw = [e.to_dict() for e in events]
    stats = ingest(db, raw)
    assert stats["failed"] == 0, f"seeding failed: {stats}"
    assert stats["ingested"] + stats["duplicates"] == len(events), f"seeding incomplete: {stats}"


def row_to_event(row) -> EVENT:
    """Reconstruct the canonical EVENT from a stored v2_events row.

    The stored row is the enriched, persisted truth - detection must
    evaluate exactly what the store contains (never a re-normalized copy).
    """
    return EVENT(
        timestamp=row.timestamp,
        host=row.host or "-",
        user=row.user or "-",
        source=row.source or "unknown",
        action=row.action or "-",
        facts=row.facts or {},
        org=row.org or "",
        raw=row.raw_json,
        integrity=row.integrity or "complete",
        event_id=row.event_id or "",
        event_type=row.event_type or "",
        destination=row.destination or "",
        process=row.process or {},
        network=row.network or {},
        outcome=row.outcome or "",
        schema_version=row.schema_version or "1.1",
    )


def stored_events(db) -> list[EVENT]:
    """All stored v2 events in deterministic order (arrival order)."""
    from sqlalchemy import select

    from backend.telemetry.models import TelemetryEvent

    rows = db.scalars(
        select(TelemetryEvent).order_by(TelemetryEvent.timestamp, TelemetryEvent.id)
    ).all()
    return [row_to_event(r) for r in rows]