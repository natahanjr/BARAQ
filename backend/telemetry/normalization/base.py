"""v2 normalization (Phase 1).

Converts raw collector records into canonical :class:`EVENT` objects.

Owned by ``telemetry/normalization``. May only consume raw records and the
EVENT contract; never reads detection state and never writes anywhere.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Protocol

from backend.telemetry.contract import EVENT

_REQUIRED = ("timestamp", "host", "user", "source", "action")

#: Canonical event_type derivation for records that do not carry one
#: (Phase 2: the detection surface needs a canonical event_type; the
#: fingerprint never includes event_type, so this is additive and does not
#: change dedup or replay semantics).
_EVENT_TYPE_BY_ACTION: tuple[tuple[str, str], ...] = (
    ("authentication", "logon"),
    ("authentication", "logon_failed"),
    ("authentication", "logoff"),
    ("authentication", "logon_success"),
    ("authentication", "auth"),
    ("authentication", "authenticate"),
    ("authentication", "logout"),
    ("process", "create_process"),
    ("process", "process_created"),
    ("process", "process_start"),
    ("process", "process_stop"),
    ("process", "process_exit"),
    ("file", "file_modify"),
    ("file", "file_write"),
    ("file", "file_create"),
    ("file", "file_rename"),
    ("file", "file_delete"),
    ("file", "shadow_delete"),
    ("file", "shadow_copy"),
    ("network", "connect"),
    ("network", "disconnect"),
    ("network", "connection"),
    ("network", "listen"),
)


def _derive_event_type(action: str) -> str:
    """Canonical event_type for a generic record missing one, or ""."""
    if not action:
        return ""
    lowered = action.lower()
    if lowered.startswith("process_"):
        return "process"
    if lowered.startswith("file_"):
        return "file"
    if lowered.startswith("network_"):
        return "network"
    for event_type, candidate in _EVENT_TYPE_BY_ACTION:
        if candidate == lowered:
            return event_type
    return ""


class Normalizer(Protocol):
    """Anything that turns one raw record into an EVENT."""

    def supports(self, raw: dict[str, Any]) -> bool: ...

    def normalize(self, raw: dict[str, Any]) -> EVENT: ...


class GenericNormalizer:
    """Canonical JSON record in -> EVENT out.

    Accepted shapes::

        {"timestamp": iso, "host": "...", "user": "...",
         "source": "windows/sysmon/network/...", "action": "...",
         "facts": {...}, "org": "",
         "event_id": "...", "event_type": "...", "destination": "...",
         "process": {...}, "network": {...}, "outcome": "..."}

    Structured fields are passed through when present; ``facts`` is
    optional; missing/unknown fields never fail ingestion. Records without
    a parseable timestamp use the batch ``fallback_ts`` so fingerprints
    stay deterministic (idempotent replay).
    """

    def supports(self, raw: dict[str, Any]) -> bool:
        return isinstance(raw, dict) and "action" in raw

    def normalize(self, raw: dict[str, Any], fallback_ts: datetime) -> EVENT:
        ts = raw.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts is None:
            ts = fallback_ts
        if ts.tzinfo is None:
            from datetime import timezone

            ts = ts.replace(tzinfo=timezone.utc)
        return EVENT(
            timestamp=ts,
            host=str(raw.get("host", "-")),
            user=str(raw.get("user", "-")),
            source=str(raw.get("source", "unknown")),
            action=str(raw.get("action", "-")),
            facts=dict(raw.get("facts") or {}),
            org=str(raw.get("org", "")),
            raw=raw,
            integrity=raw.get("data_integrity", "complete"),
            event_id=str(raw.get("event_id", "")),
            event_type=str(raw.get("event_type", "")) or _derive_event_type(str(raw.get("action", ""))),
            destination=str(raw.get("destination", "")),
            process=dict(raw.get("process") or {}),
            network=dict(raw.get("network") or {}),
            outcome=str(raw.get("outcome", "")),
        )


class WindowsEventNormalizer:
    """Windows Security / Sysmon style records -> EVENT.

    Accepted shapes::

        {"event_id": 4625, "computer": "...", "subject_user_name": "...",
         "message": "...", "event_data": {...}}

    Populates the canonical structured fields: ``event_type``
    (authentication / process / other), ``destination`` (target host or IP),
    ``network`` (source IP), ``outcome`` (success/failure) and ``process``
    where the record carries a process name.
    """

    _LOGON_EVENTS = {4624, 4625}

    def supports(self, raw: dict[str, Any]) -> bool:
        return isinstance(raw, dict) and "event_id" in raw

    def normalize(self, raw: dict[str, Any], fallback_ts: datetime) -> EVENT:
        ts = raw.get("time_created") or raw.get("timestamp")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if ts is None:
            ts = fallback_ts
        if ts.tzinfo is None:
            from datetime import timezone

            ts = ts.replace(tzinfo=timezone.utc)
        eid = int(raw.get("event_id", 0))
        data = dict(raw.get("event_data") or {})
        if eid in self._LOGON_EVENTS:
            action = "logon" if eid == 4624 else "logon_failed"
            user = data.get("target_user_name") or data.get("subject_user_name") or "-"
            facts = {
                "logon_type": data.get("logon_type"),
                "source_ip": data.get("ip_address"),
                "target_user_name": data.get("target_user_name"),
                "workstation": data.get("workstation_name"),
            }
            event_type = "authentication"
            destination = str(data.get("workstation_name") or "")
            network = {"src_ip": data.get("ip_address")} if data.get("ip_address") else {}
            outcome = "success" if eid == 4624 else "failure"
        else:
            action = f"event_{eid}"
            user = str(raw.get("subject_user_name") or raw.get("user") or "-")
            facts = {k: v for k, v in data.items() if v is not None}
            event_type = "process" if eid == 4688 else "event"
            destination = str(data.get("workstation_name") or "")
            network = {"src_ip": data.get("ip_address")} if data.get("ip_address") else {}
            outcome = str(raw.get("outcome") or "")
        process = {}
        if eid == 4688:
            process = {"name": data.get("process_name") or data.get("new_process_name")}
        elif data.get("process_name"):
            process = {"name": data.get("process_name")}
        return EVENT(
            timestamp=ts,
            host=str(raw.get("computer") or raw.get("host") or "-"),
            user=user,
            source="windows",
            action=action,
            facts={k: v for k, v in facts.items() if v is not None},
            org=str(raw.get("org", "")),
            raw=raw,
            integrity=raw.get("data_integrity", "complete"),
            event_id=str(eid),
            event_type=event_type,
            destination=destination,
            process=process,
            network=network,
            outcome=outcome,
        )


NORMALIZERS: list[Normalizer] = [WindowsEventNormalizer(), GenericNormalizer()]


def normalize(raw: dict[str, Any], fallback_ts: datetime | None = None) -> EVENT | None:
    """Pick the first supporting normalizer and produce an EVENT.

    Never raises on unknown shapes: the generic path accepts anything with
    an ``action`` key. Everything else is dropped and ``None`` is returned -
    an unnormalizable record has no deterministic identity and must never
    be persisted (otherwise replay could not dedup it).
    """
    for normalizer in NORMALIZERS:
        try:
            if normalizer.supports(raw):
                return normalizer.normalize(raw, fallback_ts)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            continue
    return None
