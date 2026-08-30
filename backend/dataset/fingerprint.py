"""Deterministic event fingerprinting for the research dataset.

The fingerprint is the deduplication key for the dataset: the same
logical event must always produce the same fingerprint, and distinct
events must differ. Timestamp precision is capped at one minute so
logically identical events (e.g. the same failed logon retried by a
cron job) do not create duplicates merely because of sub-minute jitter.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

#: Fields used to build the fingerprint string.
_FP_PARTS = (
    ("ts", "ts"),
    ("host", "host"),
    ("event_type", "event_type"),
    ("category", "category"),
    ("user", "user"),
    ("process", "process_name"),
    ("parent", "parent_process"),
    ("cmdline", "command_line"),
    ("src_ip", "source_ip"),
    ("dst_ip", "destination_ip"),
    ("dst_port", "destination_port"),
    ("proto", "protocol"),
    ("file", "file_path"),
)


def fingerprint(attributes: dict) -> str:
    """SHA-256 fingerprint over stable, normalized event attributes."""
    parts: list[str] = []
    for key, attr in _FP_PARTS:
        value = attributes.get(attr)
        if value is None or value == "":
            continue
        parts.append(f"{key}={str(value).strip().lower()}")
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def fingerprint_timestamp(ts: datetime) -> str:
    """Timestamp with second precision, UTC - used for fingerprinting so
    sub-second clock jitter does not split logically identical events."""
    if ts is None:
        return ""
    return ts.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def fingerprint_row(ts: datetime | None, attrs: dict) -> str:
    """Fingerprint for a DB row already shaped as normalized attributes."""
    ts_clean = ts.astimezone(UTC) if ts else None
    row = dict(attrs)
    if ts_clean is not None:
        row["ts"] = ts_clean.replace(second=0, microsecond=0).isoformat()
    return fingerprint(row)
