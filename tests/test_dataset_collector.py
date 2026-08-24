"""Dataset collector tests: collection, dedup, export, splitting, retry,
integrity and target completion."""

import csv
import hashlib
import os

import pytest

from backend.config import DATASET_COLLECT_BATCH
from backend.dataset import (
    export_pending,
    pause,
    resume,
    status,
    sweep,
)
from backend.database.models import (
    DatasetCollection,
    DatasetEvent,
    DatasetExport,
    DatasetExportFile,
    NormalizedEvent,
)


@pytest.fixture(autouse=True)
def _tmp_dataset_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.dataset.exporter.DATASET_DIR", tmp_path)
    monkeypatch.setattr("backend.dataset.service.DATASET_DIR", tmp_path)
    return tmp_path


def _insert(db, records):
    from tests.fixtures import add_normalized

    add_normalized(db, records)
    db.commit()


def _logon(user, ip, event_id=4625, ts=None):
    from datetime import timedelta

    from tests.fixtures import _ts

    base = _ts(0)
    offset = timedelta(seconds=0)
    if isinstance(ts, timedelta):
        offset = ts
        ts = None

    return {
        "source": "eventlog",
        "channel": "Security",
        "event_id": event_id,
        "provider": "Microsoft-Windows-Security-Auditing",
        "message": (
            f"An account failed to log on. Subject: Security ID: NULL SID, Account Name: - "
            f"Logon Type: 3, Account For Which Logon Failed: {user}, Source Network Address: {ip}"
        ),
        "timestamp": ((ts or base) + offset).isoformat(),
        "user": user,
        "host": "TESTHOST",
        "facts": {
            "account_name": user,
            "logon_type": "3",
            "source_ip": ip,
            "SubStatus": "0xc000006a",
        },
    }


def _events(db, n, user="alice", ip="192.168.1.50"):
    recs = [
        _logon(
            user=user,
            ip=f"192.168.{(i // 250) + 1}.{10 + (i % 245)}",
            ts=__import__("datetime").timedelta(seconds=i),
        )
        for i in range(n)
    ]
    _insert(db, recs)
    return n


def _active_collection(db):
    return (
        db.query(DatasetCollection)
        .filter(DatasetCollection.status.in_(["active", "paused"]))
        .order_by(DatasetCollection.id.desc())
        .first()
    )


def _csv_rows(path):
    with open(path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        return list(reader)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------


def test_sweep_collects_and_deduplicates(db):
    _events(db, 3, user="alice")
    result = sweep(db)
    assert result["collected"] == 3
    assert result["total"] == 3

    # exact replay of a collected event -> fingerprint collision -> dedup
    replay = [
        r
        for r in db.query(NormalizedEvent).order_by(NormalizedEvent.id.asc()).limit(1).all()
        if r
    ]
    from tests.fixtures import add_normalized

    add_normalized(
        db,
        [{
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4625,
            "message": replay[0].message,
            "timestamp": replay[0].timestamp.isoformat(),
            "user": replay[0].user,
            "host": replay[0].host,
            "facts": (replay[0].raw_json or {}).get("facts", {}),
        }],
    )
    _insert(db, [_logon(user="bob", ip="10.0.0.7")])
    result = sweep(db)
    assert result["deduplicated"] >= 1
    assert result["total"] == 4


def test_sweep_is_stable_across_runs(db):
    _events(db, 2)
    sweep(db)
    before = db.query(DatasetEvent).count()
    # no new events: sweep is a no-op (cursor stays put)
    assert sweep(db)["collected"] == 0
    assert db.query(DatasetEvent).count() == before


def test_pause_stops_collection_resume_continues(db):
    sweep(db)  # create the default collection
    coll = _active_collection(db)
    pause(db)
    _events(db, 2)
    assert sweep(db)["collected"] == 0
    resume(db)
    assert sweep(db)["collected"] == 2


def test_fingerprints_are_deterministic(db):
    _events(db, 1, user="carol")
    sweep(db)
    fp1 = db.query(DatasetEvent).first().event_fingerprint
    db.query(DatasetEvent).delete()
    db.commit()
    _events(db, 1, user="carol")
    sweep(db)
    fp2 = db.query(DatasetEvent).first().event_fingerprint
    assert fp1 == fp2


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------


def test_export_writes_csv_checksum_and_manifest(db, _tmp_dataset_dir):
    _events(db, 5)
    sweep(db)
    coll = _active_collection(db)
    result = export_pending(db, coll.id, trigger="manual")
    assert result["status"] == "completed"
    assert result["event_count"] == 5
    assert coll.parts == 1

    files = db.query(DatasetExportFile).all()
    assert len(files) == 1
    f = files[0]
    assert f.filename == f"{coll.name}_part_001.csv"
    assert f.event_count == 5
    assert f.sha256 == _sha256(os.path.join(_tmp_dataset_dir, f.filename))
    assert f.status == "verified"

    rows = _csv_rows(os.path.join(_tmp_dataset_dir, f.filename))
    assert len(rows) == 5
    assert rows[0]["dataset_event_id"]
    assert rows[0]["timestamp"]
    assert rows[0]["collector_version"]

    # manifest exists and matches db
    manifest_path = os.path.join(_tmp_dataset_dir, f"{coll.name}_manifest.json")
    assert os.path.exists(manifest_path)
    import json

    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert manifest["total_events"] == 5
    assert manifest["parts"] == 1
    assert manifest["files"][0]["sha256"] == f.sha256
    assert manifest["files"][0]["event_count"] == 5

    # events marked exported
    assert db.query(DatasetEvent).filter(DatasetEvent.exported == True).count() == 5  # noqa: E712


def test_export_is_idempotent(db, _tmp_dataset_dir):
    _events(db, 4)
    sweep(db)
    coll = _active_collection(db)
    export_pending(db, coll.id)
    first_files = db.query(DatasetExportFile).count()

    export_pending(db, coll.id)  # second run, nothing new
    assert db.query(DatasetExportFile).count() == first_files
    assert db.query(DatasetEvent).filter(DatasetEvent.exported == False).count() == 0  # noqa: E712


def test_export_splits_at_boundary(db, _tmp_dataset_dir):
    _events(db, 7)
    sweep(db)
    coll = _active_collection(db)
    coll.events_per_file = 3
    db.commit()

    result = export_pending(db, coll.id)
    assert result["status"] == "completed"
    assert result["files_count"] == 3

    files = db.query(DatasetExportFile).order_by(DatasetExportFile.part_number).all()
    assert [f.part_number for f in files] == [1, 2, 3]
    assert [f.event_count for f in files] == [3, 3, 1]

    for f in files:
        rows = _csv_rows(os.path.join(_tmp_dataset_dir, f.filename))
        assert len(rows) <= 3
        assert len(rows) == f.event_count


def test_export_continues_part_numbering_across_batches(db, _tmp_dataset_dir):
    _events(db, 4)
    sweep(db)
    coll = _active_collection(db)
    coll.events_per_file = 5
    db.commit()
    export_pending(db, coll.id)
    assert db.query(DatasetExportFile).count() == 1

    _events(db, 4, user="dave")
    sweep(db)
    export_pending(db, coll.id)
    files = db.query(DatasetExportFile).order_by(DatasetExportFile.part_number).all()
    assert [f.part_number for f in files] == [1, 2]
    assert files[1].filename.endswith("_part_002.csv")

    # manifest lists every part of the collection, from both exports
    import json

    with open(os.path.join(_tmp_dataset_dir, f"{coll.name}_manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    assert manifest["parts"] == 2
    assert {f["part_number"] for f in manifest["files"]} == {1, 2}


def test_export_failure_retries_without_loss(db, _tmp_dataset_dir, monkeypatch):
    _events(db, 6)
    sweep(db)
    coll = _active_collection(db)

    real_writer = csv.DictWriter

    class FailingWriter:
        def __init__(self, *a, **kw):
            self._w = real_writer(*a, **kw)
            self._calls = 0

        def writeheader(self):
            self._w.writeheader()

        def writerow(self, row):
            self._calls += 1
            if self._calls == 3:
                raise OSError("simulated disk full")
            self._w.writerow(row)

    with monkeypatch.context() as m:
        m.setattr("backend.dataset.exporter.csv.DictWriter", FailingWriter)
        result = export_pending(db, coll.id)
    assert result["status"] == "failed"
    # nothing marked exported, partial file cleaned up
    assert db.query(DatasetEvent).filter(DatasetEvent.exported == True).count() == 0  # noqa: E712
    assert db.query(DatasetExportFile).count() == 0
    assert len(list(_tmp_dataset_dir.iterdir())) == 0
    failed = db.query(DatasetExport).filter(DatasetExport.status == "failed").first()
    assert failed is not None and failed.error_message

    # retry after the failure is fixed -> succeeds, still no duplicates
    result = export_pending(db, coll.id)
    assert result["status"] == "completed"
    assert result["event_count"] == 6
    assert db.query(DatasetEvent).filter(DatasetEvent.exported == True).count() == 6  # noqa: E712
    assert db.query(DatasetExportFile).count() == 1


# ---------------------------------------------------------------------------
# Integrity
# ---------------------------------------------------------------------------


def test_database_count_matches_csv_and_manifest(db, _tmp_dataset_dir):
    _events(db, 9)
    sweep(db)
    coll = _active_collection(db)
    coll.events_per_file = 4
    db.commit()
    export_pending(db, coll.id)

    db_total = db.query(DatasetEvent).count()
    assert db_total == 9

    csv_total = 0
    for f in db.query(DatasetExportFile).all():
        csv_total += len(_csv_rows(os.path.join(_tmp_dataset_dir, f.filename)))
        assert _sha256(os.path.join(_tmp_dataset_dir, f.filename)) == f.sha256
    assert csv_total == db_total == 9


def test_double_scheduled_export_no_duplicates(db, _tmp_dataset_dir):
    _events(db, 5)
    sweep(db)
    coll = _active_collection(db)
    export_pending(db, coll.id)
    export_pending(db, coll.id)  # scheduler double-run
    total_rows = sum(
        len(_csv_rows(os.path.join(_tmp_dataset_dir, f.filename)))
        for f in db.query(DatasetExportFile).all()
    )
    assert total_rows == 5


# ---------------------------------------------------------------------------
# Completion / target
# ---------------------------------------------------------------------------


def test_target_reached_completes_collection(db):
    sweep(db)
    coll = _active_collection(db)
    coll.target_events = 3
    db.commit()
    _events(db, 4)
    sweep(db)
    coll = db.get(DatasetCollection, coll.id)
    assert coll.status == "complete"
    assert coll.completed_at is not None
    assert coll.total_events >= 3

    # no more collection beyond the completed dataset (one batch overshoot allowed)
    _events(db, 2, user="eve")
    result = sweep(db)
    assert result["target_reached"] is True
    assert result["collected"] == 0
    assert db.query(DatasetEvent).filter(DatasetEvent.collection_id == coll.id).count() <= 3 + DATASET_COLLECT_BATCH


def test_status_reflects_progress(db):
    sweep(db)
    coll = _active_collection(db)
    coll.target_events = 10
    db.commit()
    _events(db, 2)
    sweep(db)
    st = status(db)
    assert st["enabled"] is True
    assert st["collection"]["total_events"] == 2
    assert st["remaining"] == 8
    assert st["progress_percent"] == 20.0
    assert st["next_export"] is not None


def test_new_session_after_completion(db):
    sweep(db)
    coll = _active_collection(db)
    coll.target_events = 1
    db.commit()
    _events(db, 1)
    sweep(db)
    assert db.get(DatasetCollection, coll.id).status == "complete"

    from backend.dataset import start

    result = start(db)
    assert result["status"] == "active"
    new_coll = db.get(DatasetCollection, result["collection_id"])
    assert new_coll.id != coll.id
    assert new_coll.status == "active"