"""Streaming pipeline: schema stamping, dead-letter queue, replay (roadmap 3.2)."""

from __future__ import annotations

import json
from datetime import UTC

import pytest

from backend import streaming


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch, tmp_path):
    monkeypatch.setattr(streaming, "STREAM_ENABLED", True)
    monkeypatch.setattr(streaming, "_record_queue", streaming.queue.Queue())
    monkeypatch.setattr(streaming, "_dlq_counts", {})
    monkeypatch.setattr(streaming, "_dlq_dir", str(tmp_path / "dlq"))
    yield


def test_records_stamped_with_schema_version():
    streaming.record_event({"event_id": 4625})
    record = streaming._record_queue.get_nowait()
    assert record["baraq.schema_version"] == streaming.SCHEMA_VERSION
    assert record["baraq.type"] == "event"


def test_dlq_captures_failed_sink_batch(tmp_path):
    (
        streaming._dispatch.cache_clear()
        if hasattr(streaming._dispatch, "cache_clear")
        else None
    )
    batch = [{"event_id": 1}, {"event_id": 2}]
    streaming._sinks["kafka"] = {
        "kind": "kafka",
        "fails": streaming._MAX_SINK_FAILURES - 1,
        "send": lambda b: (_ for _ in ()).throw(ConnectionError("broker down")),
    }
    streaming._dispatch(batch)
    assert "kafka" not in streaming._sinks, "sink must be suspended after max failures"
    files = list(tmp_path.glob("dlq/*.jsonl"))
    assert len(files) == 1
    lines = [json.loads(l) for l in files[0].read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 2
    assert all(l["sink"] == "kafka" for l in lines)
    assert streaming.dlq_status()["kafka"] == 2
    # status() must expose the DLQ counts
    assert streaming.status()["dlq"]["kafka"] == 2


def test_replay_dlq_requeues_records(tmp_path):
    dlq = tmp_path / "dlq"
    dlq.mkdir(parents=True, exist_ok=True)
    with open(dlq / "kafka.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"sink": "kafka", "record": {"event_id": 7}}) + "\n")
    result = streaming.replay_dlq()
    assert result["requeued"] == 1
    assert streaming._record_queue.get_nowait()["event_id"] == 7
    assert not (dlq / "kafka.jsonl").exists(), "empty DLQ file removed"


def test_replay_enqueues_from_database():
    from datetime import datetime

    from backend.database.connection import SessionLocal
    from backend.database.models import NormalizedEvent

    with SessionLocal() as db:
        ev = NormalizedEvent(
            source="replay-test",
            event_id=1,
            category="test",
            severity="low",
            message="replay me",
            timestamp=datetime.now(UTC),
        )
        db.add(ev)
        db.commit()
        event_id = ev.id
    result = streaming.replay(hours=24)
    assert result["enqueued"] >= 1
    assert streaming._record_queue.qsize() >= 1
    with SessionLocal() as db:
        db.query(NormalizedEvent).filter(NormalizedEvent.id == event_id).delete()
        db.commit()
