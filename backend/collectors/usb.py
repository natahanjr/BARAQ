"""USB / removable media collector (live only).

Reads Windows Security/Kernel-PnP events 6416 (new external device
recognised) and 6420 (removable device attached) through pywin32 and
normalizes them into ``UsbDevice`` records.

When pywin32 is not available the collector degrades gracefully and
returns no records (pure-live: no simulation fallback).
"""

from __future__ import annotations

import logging
import re

from backend.collectors.base import BaseCollector
from backend.collectors.eventlog import WindowsEventLogCollector
from backend.config import SECURITY_LOG_CHANNELS, USB_EVENT_IDS

logger = logging.getLogger("baraq.collectors.usb")


class UsbCollector(BaseCollector):
    """Detects insertion of new removable/USB storage devices."""

    name = "usb"

    def __init__(self):
        super().__init__()
        self._eventlog = WindowsEventLogCollector(
            channels=SECURITY_LOG_CHANNELS, extra_event_ids=USB_EVENT_IDS
        )

    def enabled(self) -> bool:
        return self._eventlog.enabled()

    def _parse(self, rec: dict) -> dict | None:
        message = rec.get("message", "") or ""
        device_name = rec.get("raw", {}).get("device_name", "")
        device_id = rec.get("raw", {}).get("device_id", "")

        if not device_name:
            m = re.search(r"Device Description:\s*(.+)", message)
            device_name = m.group(1).strip().rstrip(".") if m else "Unknown device"
        if not device_id:
            m = re.search(r"Device ID:\s*(\S+)", message)
            device_id = m.group(1) if m else ""

        if not device_id and "storage" not in message.lower():
            return None

        return {
            "source": "usb",
            "device_name": device_name[:256],
            "device_id": device_id[:256],
            "vendor": "",
            "serial": "",
            "timestamp": rec.get("timestamp"),
        }

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        out: list[dict] = []
        for rec in self._eventlog.collect():
            if rec.get("event_id") not in USB_EVENT_IDS:
                continue
            parsed = self._parse(rec)
            if parsed:
                out.append(parsed)
        self.logger.debug("Collected %d USB device insertion(s)", len(out))
        return out
