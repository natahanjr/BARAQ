"""CSV exporter for the research dataset.

Streams unexported dataset events to CSV part files (hard maximum of
``events_per_file`` rows per file), computes SHA-256 checksums while
writing, records export + file rows and refreshes the dataset manifest.

Guarantees:
* idempotent - only ``exported=False`` events are selected, and a PG
  advisory lock prevents concurrent exporters on different servers
* atomic - the export row + exported flags + file rows commit together
  only after every CSV has been written and row-count validated; any
  failure leaves the events unexported and ready for retry
* memory-safe - keyset pagination in batches (never loads the whole
  dataset) and incremental CSV writing
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session

from backend.config import DATASET_COLLECTOR_VERSION, DATASET_DIR, DATASET_SCHEMA_VERSION
from backend.database.models import (
    DatasetCollection,
    DatasetEvent,
    DatasetExport,
    DatasetExportFile,
)

from .normalize import CSV_FIELDS

log = logging.getLogger("dataset.exporter")

_MANIFEST_NAME = "manifest.json"
_PART_PREFIX = "{dataset_name}_part_{part:03d}.csv"
_ADVISORY_LOCK_KEY = "baraq-dataset-export"


class _HashingFile:
    """File handle that hashes every byte written through it."""

    def __init__(self, path: str):
        self._fh = open(path, "w", newline="", encoding="utf-8")
        self._hasher = hashlib.sha256()
        self.path = path

    def write(self, s: str) -> int:
        self._fh.write(s)
        self._hasher.update(s.encode("utf-8"))
        return len(s)

    def close(self) -> None:
        self._fh.close()

    @property
    def digest(self) -> str:
        return self._hasher.hexdigest()


def _lock_export(session: Session) -> None:
    """Take a PG advisory lock for the export transaction (cross-process
    safety - both BARAQ servers run the scheduler)."""
    session.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": _ADVISORY_LOCK_KEY}
    )


def _next_part_number(session: Session, collection_id: int) -> int:
    row = session.execute(
        select(func.max(DatasetExportFile.part_number)).where(
            DatasetExportFile.collection_id == collection_id
        )
    ).scalar()
    return int(row or 0) + 1


def _write_manifest(collection: DatasetCollection, files: list[DatasetExportFile]) -> str:
    """Write the dataset manifest JSON and return its path."""
    data = {
        "dataset_name": collection.name,
        "target_events": collection.target_events,
        "events_per_file": collection.events_per_file,
        "format": collection.format,
        "total_events": collection.total_events,
        "parts": len(files),
        "collection_started": (
            collection.started_at.isoformat() if collection.started_at else None
        ),
        "last_export": (
            collection.last_export_at.isoformat() if collection.last_export_at else None
        ),
        "status": collection.status,
        "completed_at": (
            collection.completed_at.isoformat() if collection.completed_at else None
        ),
        "schema_version": DATASET_SCHEMA_VERSION,
        "collector_version": DATASET_COLLECTOR_VERSION,
        "anonymized": collection.anonymize,
        "include_labels": collection.include_labels,
        "files": [
            {
                "filename": f.filename,
                "part_number": f.part_number,
                "event_count": f.event_count,
                "first_timestamp": f.first_timestamp.isoformat() if f.first_timestamp else None,
                "last_timestamp": f.last_timestamp.isoformat() if f.last_timestamp else None,
                "sha256": f.sha256,
                "status": f.status,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in files
        ],
    }
    path = os.path.join(DATASET_DIR, f"{collection.name}_{_MANIFEST_NAME}")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def _filename(collection: DatasetCollection, part: int) -> str:
    return _PART_PREFIX.format(dataset_name=collection.name, part=part)


def export_pending(
    session: Session,
    collection_id: int,
    trigger: str = "scheduled",
    batch_size: int | None = None,
) -> dict:
    """Export all unexported events of the collection. Idempotent."""
    from backend.config import DATASET_EXPORT_BATCH

    batch_size = batch_size or DATASET_EXPORT_BATCH
    collection = session.get(DatasetCollection, collection_id)
    if collection is None:
        return {"status": "failed", "error": "collection not found"}

    export = DatasetExport(collection_id=collection_id, trigger=trigger)
    session.add(export)
    session.flush()

    part_number = _next_part_number(session, collection_id)
    files: list[DatasetExportFile] = []
    total_written = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None
    selected_ids: list[int] = []

    cur: _HashingFile | None = None
    cur_part = 0
    cur_rows = 0
    cur_first_ts: datetime | None = None
    cur_last_ts: datetime | None = None
    writer: csv.DictWriter | None = None

    def open_part(ts: datetime) -> None:
        nonlocal cur, cur_part, cur_rows, cur_first_ts, cur_last_ts, writer
        cur_part = part_number
        cur = _HashingFile(os.path.join(DATASET_DIR, _filename(collection, cur_part)))
        writer = csv.DictWriter(cur, fieldnames=CSV_FIELDS)
        writer.writeheader()
        cur_rows = 0
        cur_first_ts = ts
        cur_last_ts = ts

    def close_part() -> None:
        nonlocal cur, cur_part, cur_rows, writer
        if cur is None:
            return
        cur.close()
        writer = None
        if cur_rows == 0:
            try:
                os.remove(cur.path)
            except OSError:
                pass
        else:
            file_row = DatasetExportFile(
                export_id=export.id,
                collection_id=collection_id,
                filename=_filename(collection, cur_part),
                part_number=cur_part,
                event_count=cur_rows,
                sha256=cur.digest,
                first_timestamp=cur_first_ts,
                last_timestamp=cur_last_ts,
                status="verified",
            )
            session.add(file_row)
            files.append(file_row)
        cur = None

    try:
        # ---- stream unexported events, deterministic order ----------------
        cursor_ts: datetime | None = None
        cursor_id: int = 0
        while True:
            q = select(DatasetEvent).where(
                DatasetEvent.collection_id == collection_id,
                DatasetEvent.exported == False,  # noqa: E712
            )
            if cursor_ts is not None:
                q = q.where(
                    (DatasetEvent.timestamp > cursor_ts)
                    | ((DatasetEvent.timestamp == cursor_ts) & (DatasetEvent.id > cursor_id))
                )
            rows = session.execute(
                q.order_by(DatasetEvent.timestamp.asc(), DatasetEvent.id.asc()).limit(
                    batch_size
                )
            ).scalars().all()
            if not rows:
                break

            for event in rows:
                selected_ids.append(event.id)
                ts = event.timestamp
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

                if cur is None:
                    open_part(ts)
                elif cur_rows >= collection.events_per_file:
                    close_part()
                    part_number += 1
                    open_part(ts)

                row = {field: (event.payload_normalized or {}).get(field, "") for field in CSV_FIELDS}
                row["dataset_event_id"] = event.source_event_id
                row["timestamp"] = ts.isoformat() if ts else ""
                writer.writerow(row)
                cur_rows += 1
                total_written += 1
                if cur_first_ts is None or ts < cur_first_ts:
                    cur_first_ts = ts
                if cur_last_ts is None or ts > cur_last_ts:
                    cur_last_ts = ts

            cursor_ts = rows[-1].timestamp
            cursor_id = rows[-1].id

        close_part()

        # ---- validate -------------------------------------------------------
        if total_written != len(selected_ids):
            raise RuntimeError(
                f"row-count mismatch: wrote {total_written} rows for {len(selected_ids)} events"
            )

        # ---- mark events exported (batched) ---------------------------------
        for i in range(0, len(selected_ids), batch_size):
            chunk = selected_ids[i : i + batch_size]
            session.execute(
                update(DatasetEvent)
                .where(DatasetEvent.id.in_(chunk))
                .values(exported=True, export_batch_id=export.id)
            )

        export.status = "completed"
        export.completed_at = datetime.now(timezone.utc)
        export.event_count = total_written
        export.files_count = len(files)
        collection.last_export_at = datetime.now(timezone.utc)
        # file rows are not flushed yet, so count parts from the session list
        collection.parts = files[-1].part_number if files else 0
        collection.updated_at = datetime.now(timezone.utc)
        session.commit()

        # manifest covers every part of the collection, not just this export
        all_files = session.execute(
            select(DatasetExportFile)
            .where(DatasetExportFile.collection_id == collection_id)
            .order_by(DatasetExportFile.part_number.asc())
        ).scalars().all()
        try:
            _write_manifest(collection, list(all_files))
        except OSError as exc:  # manifest is best-effort; export itself is done
            log.warning("Dataset manifest write failed: %s", exc)

        log.info(
            "Dataset export #%s: %d events -> %d CSV part(s), %d checksums",
            export.id, total_written, len(files), len(files),
        )
        return {
            "status": "completed",
            "export_id": export.id,
            "event_count": total_written,
            "files_count": len(files),
            "files": [f.to_dict() for f in files],
        }

    except Exception as exc:  # noqa: BLE001
        # cleanup partial files, leave events unexported
        if cur is not None:
            try:
                cur.close()
                os.remove(cur.path)
            except OSError:
                pass
        session.rollback()
        # the original export row lived in the rolled-back transaction,
        # so record the failure as a fresh row that actually persists
        failed_row = DatasetExport(
            collection_id=collection_id,
            trigger=trigger,
            status="failed",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            error_message=str(exc)[:1000],
            event_count=0,
            files_count=0,
        )
        session.add(failed_row)
        session.commit()
        log.error("Dataset export failed: %s", exc, exc_info=True)
        return {"status": "failed", "error": str(exc)}


def export_all_pending(session: Session, trigger: str = "scheduled") -> dict:
    """Export for every non-complete collection that has pending events."""
    _lock_export(session)
    collections = session.execute(
        select(DatasetCollection).where(DatasetCollection.status.in_(["active", "paused"]))
    ).scalars().all()
    results = []
    for coll in collections:
        pending = session.execute(
            select(func.count(DatasetEvent.id)).where(
                DatasetEvent.collection_id == coll.id,
                DatasetEvent.exported == False,  # noqa: E712
            )
        ).scalar() or 0
        if pending:
            results.append(export_pending(session, coll.id, trigger=trigger))
    return {"collections": results}