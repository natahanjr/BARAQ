"""CVE database loader + product/version matching engine."""
from __future__ import annotations

import json
import logging
from pathlib import Path

from backend.vulnscan.version import version_lt

logger = logging.getLogger("baraq.vulnscan")

CVE_DB_PATH = Path(__file__).resolve().parent / "cves.json"

MATCH_ONLY_ENTRIES = {
    "CVE-2023-44487",
    "CVE-2021-34527",
    "CVE-2017-0144",
    "CVE-2019-0708",
}


def load_cves(path: Path | None = None) -> list[dict]:
    """Load the curated CVE list from disk."""
    try:
        data = json.loads((path or CVE_DB_PATH).read_text(encoding="utf-8"))
        return list(data.get("cves", []))
    except (OSError, ValueError) as exc:
        logger.warning("CVE database %s unreadable: %s", path or CVE_DB_PATH, exc)
        return []


def match_product(product_name: str, version: str, cves: list[dict]) -> list[dict]:
    """Return the CVEs applicable to one installed product."""
    hits: list[dict] = []
    name = (product_name or "").lower()
    for cve in cves:
        needle = (cve.get("match") or "").lower()
        if not needle or needle not in name:
            continue
        upper = cve.get("version_lt")
        if upper and upper != "999.0":
            if not version:
                continue
            if not version_lt(version, upper):
                continue
        hits.append(cve)
    return hits


def scan_inventory(inventory: dict, cves: list[dict] | None = None) -> list[dict]:
    """Match a host inventory against the CVE database.

    Returns findings: one entry per (product, CVE) hit, sorted by CVSS.
    """
    cves = cves if cves is not None else load_cves()
    findings: list[dict] = []
    for product in inventory.get("products", []):
        name = product.get("name") or ""
        version = product.get("version") or ""
        for cve in match_product(name, version, cves):
            findings.append(
                {
                    "product": name,
                    "version": version,
                    "cve_id": cve["cve_id"],
                    "cvss": float(cve.get("cvss", 0.0)),
                    "severity": cve.get("severity", "medium"),
                    "description": cve.get("description", ""),
                    "remediation": cve.get("remediation", ""),
                }
            )
    findings.sort(key=lambda f: f["cvss"], reverse=True)
    return findings
