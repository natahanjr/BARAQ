"""Windows Event Log collector (Security + System channels) via pywin32.

Reads the live Windows event log using win32evtlog. If pywin32 is not
available (e.g. non-Windows test machine) the collector degrades gracefully
and returns no records so the pipeline can still run on simulated data.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime, timedelta, timezone

from backend.collectors.base import BaseCollector
from backend.config import (
    EVENT_LOG_POLL_BATCH,
    POWERSHELL_CHANNELS,
    SECURITY_LOG_CHANNELS,
)

logger = logging.getLogger("sentinel.collectors.eventlog")

try:
    import win32evtlog
    import win32evtlogutil

    HAS_PYWIN32 = True
except ImportError:  # pragma: no cover - non-Windows fallback
    HAS_PYWIN32 = False

#: Event IDs whose string values (command line, script block) are commonly
#: truncated by the legacy message formatter and must be fetched structurally.
STRUCTURED_FIELDS_EVENT_IDS = {4688, 4104, 4103, 4698, 7045}


class WindowsEventLogCollector(BaseCollector):
    """Collects raw Windows Event Log records from configured channels."""

    name = "eventlog"

    #: Event IDs that carry security relevance for the normalizer.
    INTERESTING_EVENT_IDS = {
        4624, 4625, 4634, 4647, 4648, 4672, 4688, 4720, 4722, 4724, 4725,
        4726, 4728, 4732, 4734, 4740, 4768, 4769, 4771, 4698, 4702,
        7045, 7040, 7036,
    }

    def __init__(self, channels: list[str] | None = None, extra_event_ids: set[int] | None = None):
        super().__init__()
        self.channels = channels or [*SECURITY_LOG_CHANNELS, *POWERSHELL_CHANNELS]
        self._extra_event_ids = set(extra_event_ids or set())
        self._last_read: dict[str, int] = {}  # channel -> record number

    def _relevant(self, event_id: int) -> bool:
        return event_id in self.INTERESTING_EVENT_IDS or event_id in self._extra_event_ids

    def enabled(self) -> bool:
        return HAS_PYWIN32

    # ------------------------------------------------------------------
    def _open_channel(self, channel: str):
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        handle = win32evtlog.OpenEventLog(None, channel)
        return handle, flags

    def _safe_message(self, handle, event, channel: str) -> str:
        """Extract the event message text defensively."""
        try:
            return win32evtlogutil.SafeFormatMessage(event, channel)
        except Exception:
            try:
                return win32evtlogutil.FormatMessage(event, channel)
            except Exception:
                return ""

    # ------------------------------------------------------------------
    def _structured_fields(self, channel: str, record_number: int) -> dict:
        """Full structured fields for events whose string values the legacy
        message formatter truncates (4688 command line, 4104 script block).

        Queries the event by record number through the structured event API
        (``EvtQuery``/``EvtRender``) so ``<Data Name=...>`` values arrive
        complete - exactly what SafeFormatMessage cuts short.
        """
        if not HAS_PYWIN32:
            return {}
        try:
            query = f"*[System[EventRecordID={int(record_number)}]]"
            handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath, query)
        except Exception as exc:  # noqa: BLE001
            logger.debug("structured query failed for %s/%s: %s", channel, record_number, exc)
            return {}
        try:
            events = win32evtlog.EvtNext(handle, 1)
            if not events:
                return {}
            xml = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
            return self._parse_data_xml(xml)
        except Exception as exc:  # noqa: BLE001
            logger.debug("structured render failed for %s/%s: %s", channel, record_number, exc)
            return {}
        finally:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _parse_data_xml(xml: str) -> dict:
        """Extract ``<Data Name="X">value</Data>`` pairs from event XML."""
        if not xml:
            return {}
        fields: dict[str, str] = {}
        for m in re.finditer(r"<Data\s+Name=[\"']([^\"']+)[\"']>(.*?)</Data>", xml, re.DOTALL):
            name, value = m.group(1), m.group(2)
            value = value.strip()
            if value and name not in fields:
                fields[name] = value
        return fields

    def _parse_record(self, event) -> dict | None:
        event_id = event.EventID & 0xFFFFFFFF
        if not self._relevant(event_id):
            return None

        ts = event.TimeGenerated
        timestamp = datetime.fromtimestamp(
            ts, tz=timezone.utc
        ).isoformat() if isinstance(ts, float) else ts.isoformat()

        return {
            "source": "eventlog",
            "channel": "unknown",
            "event_id": event_id,
            "timestamp": timestamp,
            "user": "-",
            "message": "",
            "raw": {
                "provider": event.SourceName,
                "category": event.EventCategory,
                "event_type": event.EventType,
                "computer": event.ComputerName,
                "record_number": event.RecordNumber,
            },
        }

    # ------------------------------------------------------------------
    def collect(self) -> list[dict]:
        if not self.enabled():
            self.logger.debug("pywin32 unavailable; skipping live event log read")
            return []

        records: list[dict] = []
        for channel in self.channels:
            try:
                records.extend(self._collect_channel(channel))
            except Exception as exc:  # noqa: BLE001
                self.logger.warning("Channel %s read failed: %s", channel, exc)
        return records

    def _collect_channel(self, channel: str) -> list[dict]:
        handle, flags = self._open_channel(channel)
        out: list[dict] = []
        try:
            # First poll: read the newest batch. Later polls: resume FORWARD
            # from the last record number so no event is ever skipped when the
            # channel volume between polls exceeds the batch cap.
            seek = getattr(win32evtlog, "SeekEventLog", None)
            if seek is not None and channel in self._last_read:
                seek(
                    handle, self._last_read[channel] + 1, 0,
                    win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ,
                )
                read_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            else:
                read_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events = win32evtlog.ReadEventLog(handle, read_flags, 0)
            for event in events:
                rec = self._parse_record(event)
                if rec:
                    rec["channel"] = channel
                    rec["message"] = self._safe_message(handle, event, channel)[:8192]
                    if rec["event_id"] in STRUCTURED_FIELDS_EVENT_IDS:
                        structured = self._structured_fields(channel, event.RecordNumber)
                        if structured:
                            rec["raw"].update(structured)
                    out.append(rec)
                self._last_read[channel] = event.RecordNumber
                if len(out) >= EVENT_LOG_POLL_BATCH:
                    break
        finally:
            win32evtlog.CloseEventLog(handle)
        self.logger.debug("Read %d raw records from %s", len(out), channel)
        return out