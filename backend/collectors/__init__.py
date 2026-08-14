"""Collector registry - unified entry point for the collection layer."""
from __future__ import annotations

import logging

from backend.collectors.base import BaseCollector
from backend.collectors.dns_http import DnsHttpCollector
from backend.collectors.email import EmailCollector
from backend.collectors.eventlog import WindowsEventLogCollector
from backend.collectors.malware import MalwareFileCollector
from backend.collectors.network import NetworkCollector
from backend.collectors.powershell import PowerShellCollector
from backend.collectors.process import ProcessCollector
from backend.collectors.sysmon import SysmonCollector
from backend.collectors.usb import UsbCollector
from backend.collectors.vulnscan import VulnScanCollector

logger = logging.getLogger("baraq.collectors")


class CollectorManager:
    """Runs every enabled collector and returns the raw record batch."""

    def __init__(self):
        self.collectors: list[BaseCollector] = [
            WindowsEventLogCollector(),
            PowerShellCollector(),
            ProcessCollector(),
            NetworkCollector(),
            SysmonCollector(),
            DnsHttpCollector(),
            EmailCollector(),
            UsbCollector(),
            MalwareFileCollector(),
            VulnScanCollector(),
        ]

    def collect(self) -> list[dict]:
        from backend.collectors.health import registry

        records: list[dict] = []
        for collector in self.collectors:
            try:
                if collector.enabled():
                    records.extend(collector.collect())
            except Exception as exc:  # noqa: BLE001
                logger.warning("Collector %s failed: %s", collector.name, exc)
                registry.record_failure(collector.name, str(exc))
        logger.info("Collector manager returned %d raw records", len(records))
        return records

    def health(self) -> dict:
        """Per-collector + per-channel health snapshot for the API."""
        from backend.collectors.health import registry

        return {
            "collectors": [
                {
                    "name": collector.name,
                    "enabled": collector.enabled(),
                }
                for collector in self.collectors
            ],
            "channels": registry.snapshot(),
        }
