"""Sysmon collector - process tree / network / file activity.

Reads the live Microsoft-Windows-Sysmon/Operational channel via pywin32
and maps the highest-value event types onto the pipeline's native record
shapes:

  * Event 1  (Process Create)      -> "process" source (pid/ppid tree)
  * Event 3  (Network Connect)     -> "network" source
  * Event 10 (Process Access)      -> "eventlog" Event 10 (LSASS / credential access)
  * Event 11 (File Create)         -> "eventlog" Event 11 (file staging/binary drop)
  * Event 13 (Registry Event)      -> "eventlog" Event 13 (Run-key persistence)
  * Event 23 (File Delete)         -> "eventlog" Event 23 (delete churn / cleanup)

So when Sysmon (or pywin32) is not installed the collector degrades
gracefully and returns no records, exactly like the event log collector.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

from backend.collectors.base import BaseCollector
from backend.collectors.health import PRIVILEGE_NOT_HELD, registry, retry_with_backoff
from backend.config import EVENT_LOG_POLL_BATCH, INCREMENTAL_COLLECTION, SYSMON_CHANNELS

logger = logging.getLogger("baraq.collectors.sysmon")

try:
    import win32evtlog
    import win32evtlogutil

    HAS_PYWIN32 = True
except ImportError:  # pragma: no cover - non-Windows fallback
    HAS_PYWIN32 = False

_FIELD = {
    "image": re.compile(r"Image:\s+(\S+)", re.IGNORECASE),
    "command_line": re.compile(r"CommandLine:\s+(.+)", re.IGNORECASE),
    "parent_image": re.compile(r"ParentImage:\s+(\S+)", re.IGNORECASE),
    "user": re.compile(r"User:\s+(\S+)", re.IGNORECASE),
    "protocol": re.compile(r"Protocol:\s+(\S+)", re.IGNORECASE),
    "source_ip": re.compile(r"SourceIp:\s+(\S+)", re.IGNORECASE),
    "source_port": re.compile(r"SourcePort:\s+(\d+)", re.IGNORECASE),
    "dest_ip": re.compile(r"DestinationIp:\s+(\S+)", re.IGNORECASE),
    "dest_port": re.compile(r"DestinationPort:\s+(\d+)", re.IGNORECASE),
    "target_filename": re.compile(r"TargetFilename:\s+(\S+)", re.IGNORECASE),
    "hashes": re.compile(r"Hashes:\s+(\S+)", re.IGNORECASE),
    "fqdn": re.compile(r"QueryName:\s+(\S+)", re.IGNORECASE),
    "target_image": re.compile(r"TargetImage:\s+(\S+)", re.IGNORECASE),
    "granted_access": re.compile(r"GrantedAccess:\s+(\S+)", re.IGNORECASE),
    "target_object": re.compile(r"TargetObject:\s+(\S+)", re.IGNORECASE),
    "event_type": re.compile(r"EventType:\s+(\S+)", re.IGNORECASE),
    "details": re.compile(r"Details:\s+(.+)", re.IGNORECASE),
}


def _match(text: str, key: str) -> str:
    m = _FIELD[key].search(text or "")
    return m.group(1).strip().rstrip(",") if m else ""


class SysmonCollector(BaseCollector):
    """Collects process / network / file telemetry from the Sysmon channel."""

    name = "sysmon"

    #: Sysmon event IDs this collector cares about.
    EVENT_IDS = {1, 3, 10, 11, 13, 23}

    def __init__(self, channels: list[str] | None = None):
        super().__init__()
        self.channels = channels or list(SYSMON_CHANNELS)
        self._last_read: dict[str, int] = {}

    def enabled(self) -> bool:
        return HAS_PYWIN32

    # ------------------------------------------------------------------
    def _to_records(self, event) -> list[dict]:
        event_id = event.EventID & 0xFFFFFFFF
        if event_id not in self.EVENT_IDS:
            return []
        ts = event.TimeGenerated
        timestamp = (
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            if isinstance(ts, float)
            else ts.isoformat()
        )
        message = ""
        try:
            message = win32evtlogutil.SafeFormatMessage(event) or win32evtlogutil.FormatMessage(event)
        except Exception:  # noqa: BLE001
            message = ""

        if event_id == 1:  # Process Create -> process tree
            image = _match(message, "image")
            cmdline = _match(message, "command_line")
            if not image:
                return []
            return [{
                "source": "process",
                "pid": event.EventID and _pid_from_message(message, event),
                "ppid": _ppid_from_message(message),
                "name": image.rsplit("\\", 1)[-1],
                "path": image,
                "cmdline": cmdline,
                "parent_name": _match(message, "parent_image").rsplit("\\", 1)[-1],
                "user": _match(message, "user"),
                "is_new": True,
                "timestamp": timestamp,
                "raw": {
                    "cmdline": cmdline,
                    "parent_image": _match(message, "parent_image"),
                },
            }]

        if event_id == 3:  # Network Connect -> network source
            dest_ip = _match(message, "dest_ip")
            if not dest_ip:
                return []
            state = "connected"
            if _match(message, "dest_port"):
                state += f"/{_match(message, 'protocol')}" if _match(message, "protocol") else ""
            return [{
                "source": "network",
                "pid": _pid_from_message(message, event),
                "process": _match(message, "image").rsplit("\\", 1)[-1] or "unknown",
                "local_ip": _match(message, "source_ip"),
                "local_port": int(_match(message, "source_port") or 0),
                "remote_ip": dest_ip,
                "remote_port": int(_match(message, "dest_port") or 0),
                "state": state,
                "is_listening": False,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "duration_seconds": 0.0,
                "timestamp": timestamp,
            }]

        if event_id == 10:  # Process Access -> credential-access signal (Event 10)
            target_image = _match(message, "target_image")
            if not target_image:
                return []
            image = _match(message, "image")
            return [{
                "source": "eventlog",
                "channel": "Sysmon",
                "event_id": 10,
                "timestamp": timestamp,
                "user": _match(message, "user") or "-",
                "message": f"Process accessed: {target_image} by {image} (GrantedAccess: {_match(message, 'granted_access')})",
                "raw": {
                    "computer": event.ComputerName,
                    "record_number": event.RecordNumber,
                    "sysmon_event_id": 10,
                    "image": image,
                    "target_image": target_image,
                    "granted_access": _match(message, "granted_access") or "0x0",
                },
            }]

        if event_id == 13:  # Registry Value Set -> persistence signal (Event 13)
            target_object = _match(message, "target_object")
            if not target_object:
                return []
            image = _match(message, "image")
            event_type = _match(message, "event_type") or "SetValue"
            details = _match(message, "details")
            return [{
                "source": "eventlog",
                "channel": "Sysmon",
                "event_id": 13,
                "timestamp": timestamp,
                "user": _match(message, "user") or "-",
                "message": (
                    f"Registry value {event_type}: {target_object} = "
                    f"{details or '<deleted>'} by {image}"
                ),
                "raw": {
                    "computer": event.ComputerName,
                    "record_number": event.RecordNumber,
                    "sysmon_event_id": 13,
                    "image": image,
                    "target_object": target_object,
                    "event_type": event_type,
                    "details": details or "",
                },
            }]

        # File events (11 create / 23 delete) -> normalized events so the
        # data-staging rule and normalizer risk model can reason over them.
        target = _match(message, "target_filename")
        if not target:
            return []
        return [{
            "source": "eventlog",
            "channel": "Sysmon",
            "event_id": event_id,
            "timestamp": timestamp,
            "user": _match(message, "user") or "-",
            "message": f"File {'created' if event_id == 11 else 'deleted'}: {target}",
            "raw": {
                "computer": event.ComputerName,
                "record_number": event.RecordNumber,
                "sysmon": {
                    "event_id": event_id,
                    "file_path": target,
                    "hashes": _match(message, "hashes"),
                    "image": _match(message, "image"),
                },
            },
        }]

    # ------------------------------------------------------------------
    def collect(self) -> list[dict]:
        if not self.enabled():
            self.logger.debug("pywin32 unavailable; skipping Sysmon read")
            return []

        records: list[dict] = []
        for channel in self.channels:
            try:
                channel_records = self._collect_channel(channel)
                records.extend(channel_records)
                registry.record_success(channel, len(channel_records))
            except Exception as exc:  # noqa: BLE001
                winerror = getattr(exc, "winerror", None)
                if isinstance(winerror, tuple):
                    winerror = winerror[0]
                if winerror == PRIVILEGE_NOT_HELD:
                    self.logger.error(
                        "Sysmon channel %s read failed: missing privilege "
                        "(win32 error 1314). Run scripts\\elevate_permissions.ps1 "
                        "grant or run elevated, then restart.",
                        channel,
                    )
                else:
                    self.logger.warning("Sysmon channel %s read failed: %s", channel, exc)
                registry.record_failure(channel, str(exc), permission_issue=winerror == PRIVILEGE_NOT_HELD)
        return records

    def _collect_channel(self, channel: str) -> list[dict]:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handle = win32evtlog.OpenEventLog(None, channel)
        out: list[dict] = []
        try:
            seek = getattr(win32evtlog, "SeekEventLog", None)
            if INCREMENTAL_COLLECTION and seek is not None and channel in self._last_read:
                seek(
                    handle, self._last_read[channel], 0,
                    win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ,
                )
            events = retry_with_backoff(
                lambda: win32evtlog.ReadEventLog(handle, flags, 0),
                attempts=3,
            )
            for event in events:
                out.extend(self._to_records(event))
                self._last_read[channel] = event.RecordNumber
                if len(out) >= EVENT_LOG_POLL_BATCH:
                    break
        finally:
            win32evtlog.CloseEventLog(handle)
        self.logger.debug("Read %d raw records from %s", len(out), channel)
        return out


def _pid_from_message(message: str, event) -> int:
    """ProcessId appears in the event Data fields; fall back to 0."""
    m = re.search(r"ProcessId:\s+(\d+)", message or "", re.IGNORECASE)
    if m:
        return int(m.group(1))
    try:
        return int(event.StringInserts[2]) if getattr(event, "StringInserts", None) else 0
    except (TypeError, ValueError, IndexError):
        return 0


def _ppid_from_message(message: str) -> int:
    m = re.search(r"ParentProcessId:\s+(\d+)", message or "", re.IGNORECASE)
    return int(m.group(1)) if m else 0