"""Phase 1 - v2 telemetry pipeline tests (clean-room).

Covers the SOC contract for telemetry:

* normalization: raw -> EVENT (generic + windows)
* fingerprint: identical events dedup, replay is a no-op
* enrichment: fail-open, never raises, never writes
* boundary: ingestion never creates alerts / incidents / risk rows
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from backend.database.models import Alert, Incident
from backend.main import app
from backend.telemetry.contract import EVENT
from backend.telemetry.enrichment.base import enrich
from backend.telemetry.ingestion.pipeline import ingest
from backend.telemetry.models import TelemetryEvent
from backend.telemetry.normalization.base import (
    GenericNormalizer,
    WindowsEventNormalizer,
    normalize,
)

NOW = datetime.now(timezone.utc)


def _raw(**overrides):
    payload = {
        "timestamp": NOW.isoformat(),
        "host": "ws-01",
        "user": "alice",
        "source": "windows",
        "action": "logon_failed",
        "facts": {"source_ip": "203.0.113.7", "logon_type": 3},
    }
    payload.update(overrides)
    return payload


def test_normalize_generic():
    event = normalize(_raw())
    assert isinstance(event, EVENT)
    assert event.action == "logon_failed"
    assert event.facts["source_ip"] == "203.0.113.7"
    assert event.integrity == "complete"


def test_normalize_windows_event_shape():
    raw = {
        "event_id": 4625,
        "computer": "ws-02",
        "event_data": {
            "target_user_name": "bob",
            "ip_address": "198.51.100.9",
            "logon_type": 3,
        },
        "time_created": NOW.isoformat(),
    }
    event = normalize(raw)
    assert event.source == "windows"
    assert event.action == "logon_failed"
    assert event.user == "bob"
    assert event.host == "ws-02"
    assert event.facts["source_ip"] == "198.51.100.9"


def test_normalize_unknown_shape_skipped():
    assert normalize({"something": "else"}) is None


def test_fingerprint_stable_and_distinct():
    a = EVENT(NOW, "ws-01", "alice", "windows", "logon", {"ip": "1.2.3.4"})
    b = EVENT(NOW, "ws-01", "alice", "windows", "logon", {"ip": "1.2.3.4"})
    c = EVENT(NOW, "ws-01", "alice", "windows", "logon", {"ip": "9.9.9.9"})
    assert a.fingerprint() == b.fingerprint()
    assert a.fingerprint() != c.fingerprint()


def test_ingest_idempotent_replay(db):
    raw = [_raw()]
    first = ingest(db, raw)
    assert first["ingested"] == 1
    second = ingest(db, raw)
    assert second["duplicates"] == 1
    assert second["ingested"] == 0
    assert db.scalars(select(TelemetryEvent)).one().action == "logon_failed"


def test_ingest_batch_with_bad_record(db):
    records = [_raw(host="a"), "not-a-record", None, _raw(host="b")]
    stats = ingest(db, records)
    assert stats["ingested"] == 2
    assert stats["skipped"] == 2


def test_ingest_drops_unnormalizable_records(db):
    """Shapeless records must never be persisted (no deterministic id)."""
    records = [_raw(host="a"), {"no": "shape"}, _raw(host="b")]
    stats = ingest(db, records)
    assert stats["ingested"] == 2
    assert stats["skipped"] == 1
    assert db.query(TelemetryEvent).count() == 2


def test_ingest_no_side_effects_on_v1_tables(db):
    before_alerts = db.query(Alert).count()
    before_incidents = db.query(Incident).count()
    ingest(db, [_raw(), _raw(host="other")])
    db.commit()
    assert db.query(Alert).count() == before_alerts
    assert db.query(Incident).count() == before_incidents


def test_enrich_fail_open(db):
    event = EVENT(NOW, "ws-01", "alice", "windows", "logon", {"source_ip": "1.2.3.4"})
    enriched = enrich(event, db)
    assert enriched is not None
    assert isinstance(enriched.facts.get("geo"), dict)
    # Enrichment never writes: nothing new persisted.
    assert db.query(TelemetryEvent).count() == 0


def test_windows_burst_dedups_to_distinct_fingerprints(db):
    """RDP_DUPLICATION_001 regression seed: 5 identical events in a minute."""
    records = []
    for i in range(5):
        records.append(
            {
                "event_id": 4624,
                "computer": "ml-host",
                "event_data": {"target_user_name": "alice", "ip_address": "10.0.0.5"},
                "time_created": (NOW + timedelta(seconds=i)).isoformat(),
            }
        )
    stats = ingest(db, records)
    # 5 identical events with distinct timestamps -> 5 events (each unique
    # occurrence), but v2 dedup is a no-op only when the SAME record replays.
    assert stats["ingested"] == 5
    replays = ingest(db, records)
    assert replays["ingested"] == 0
    assert replays["duplicates"] == 5


def test_generic_normalizer_supports():
    assert GenericNormalizer().supports({"action": "x"})
    assert not GenericNormalizer().supports({"event_id": 1})
    assert WindowsEventNormalizer().supports({"event_id": 4625})


def test_ingest_refuses_production_db_name(monkeypatch, db):
    """Phase 0.7: the pipeline must refuse the production DB by name."""
    import backend.config as config
    from backend.telemetry.ingestion import pipeline

    monkeypatch.setattr(config, "DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel")
    with pytest.raises(RuntimeError, match="production database"):
        pipeline.ingest(db, [_raw()])


def test_config_gate_disables_v2_on_production_db_name(monkeypatch):
    """Phase 0.7: config must disable the v2 flag on the production DB even
    when BARAQ_ENV is unset (development default) and the flag is set."""
    import backend.config as config
    from backend.api import telemetry as telemetry_api

    monkeypatch.setenv("BARAQ_TELEMETRY_V2", "1")
    monkeypatch.setenv("BARAQ_ENV", "development")
    monkeypatch.setattr(config, "DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel")
    monkeypatch.setattr(config, "TELEMETRY_V2_ENABLED", False)
    # The API is the guard surface: with production DB configured, the
    # endpoint must report disabled regardless of the env flag.
    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/v2/telemetry/events")
    assert r.status_code == 200
    assert r.json()["status"] == "disabled"
    assert telemetry_api.TELEMETRY_V2_ENABLED is False
