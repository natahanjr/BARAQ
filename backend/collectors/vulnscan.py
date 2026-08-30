"""Vulnerability collector - emits ``vuln`` records from the local scanner.

Runs the inventory + CVE matching engine and returns one record per
finding. Findings are forwarded centrally by agents using the standard
``CollectorManager``; the pipeline persists them as ``VulnFinding`` rows
which the vulnerability rule aggregates into MITRE-mapped alerts.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

from backend.collectors.base import BaseCollector
from backend.vulnscan.engine import load_cves, scan_inventory
from backend.vulnscan.inventory import host_inventory

logger = logging.getLogger("baraq.collectors.vulnscan")


class VulnScanCollector(BaseCollector):
    name = "vulnscan"

    def __init__(self, inventory: dict | None = None):
        super().__init__()
        self._inventory = inventory or {}
        self._seen: set[tuple[str, str]] = set()

    def enabled(self) -> bool:
        return os.name == "nt"

    def collect(self) -> list[dict]:
        if not self.enabled():
            return []
        inventory = self._inventory or host_inventory()
        findings = scan_inventory(inventory, load_cves())
        now = datetime.now(UTC).isoformat()
        records: list[dict] = []
        for finding in findings:
            key = (finding["product"], finding["cve_id"])
            if key in self._seen:
                continue
            self._seen.add(key)
            records.append(
                {
                    "source": "vuln",
                    "product": finding["product"],
                    "version": finding["version"],
                    "cve_id": finding["cve_id"],
                    "cvss": finding["cvss"],
                    "severity": finding["severity"],
                    "description": finding["description"],
                    "remediation": finding["remediation"],
                    "timestamp": now,
                }
            )
        self.logger.debug("Collected %d vulnerability finding(s)", len(records))
        return records
