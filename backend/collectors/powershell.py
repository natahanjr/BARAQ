"""PowerShell activity collector.

Primarily built on Windows Event Log script block/module logging
(Event 4104 / 4103) which is read through the same pywin32 mechanism.
On machines without pywin32 this collector is a no-op.
"""

from __future__ import annotations

import logging

from backend.collectors.base import BaseCollector
from backend.collectors.eventlog import WindowsEventLogCollector
from backend.config import POWERSHELL_CHANNELS

logger = logging.getLogger("baraq.collectors.powershell")


class PowerShellCollector(BaseCollector):
    """Collects PowerShell execution records (Event 4104, 4103, 400, 403)."""

    name = "powershell"

    PS_EVENT_IDS = {4104, 4103, 400, 403}

    def __init__(self):
        super().__init__()
        self._eventlog = WindowsEventLogCollector(channels=POWERSHELL_CHANNELS)

    def enabled(self) -> bool:
        return self._eventlog.enabled()

    def collect(self) -> list[dict]:
        records = []
        for rec in self._eventlog.collect():
            if rec.get("event_id") in self.PS_EVENT_IDS:
                rec["source"] = "powershell"
                rec["raw"]["script_block"] = rec["message"]
                records.append(rec)
        self.logger.debug("Collected %d PowerShell records", len(records))
        return records
