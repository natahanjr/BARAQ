"""Collector registry - unified entry point for the collection layer."""
from __future__ import annotations

import logging

from backend.collectors.base import BaseCollector
from backend.collectors.eventlog import WindowsEventLogCollector
from backend.collectors.network import NetworkCollector
from backend.collectors.powershell import PowerShellCollector
from backend.collectors.process import ProcessCollector

logger = logging.getLogger("sentinel.collectors")


class CollectorManager:
    """Runs every enabled collector and returns the raw record batch."""

    def __init__(self):
        self.collectors: list[BaseCollector] = [
            WindowsEventLogCollector(),
            PowerShellCollector(),
            ProcessCollector(),
            NetworkCollector(),
        ]

    def collect(self) -> list[dict]:
        records: list[dict] = []
        for collector in self.collectors:
            try:
                if collector.enabled():
                    records.extend(collector.collect())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Collector %s failed: %s", collector.name, exc)
        logger.info("Collector manager returned %d raw records", len(records))
        return records
