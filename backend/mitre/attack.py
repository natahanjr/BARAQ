"""MITRE ATT&CK framework data and lookups used across the platform.

Contains a curated subset of Enterprise techniques relevant to the
BARAQ detection rules. Each technique carries its MITRE ID,
tactic, description, data sources and detection/remediation advice.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("baraq.mitre")

TECHNIQUES_JSON = Path(__file__).parent / "techniques.json"

# Technique registry: MITRE ID -> record. Loaded once at import time.
TECHNIQUES: dict[str, dict] = {}


def _load() -> dict[str, dict]:
    with TECHNIQUES_JSON.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    registry = {t["id"]: t for t in data.get("techniques", [])}
    logger.info("Loaded %d MITRE ATT&CK techniques", len(registry))
    return registry


TECHNIQUES = _load()


def get_technique(mitre_id: str) -> dict | None:
    """Return the technique record for a MITRE ID (case-insensitive)."""
    key = str(mitre_id).upper()
    return TECHNIQUES.get(key)


def get_recommendation(mitre_id: str) -> str:
    tech = get_technique(mitre_id)
    if tech:
        return tech.get("recommendation", "")
    return "Investigate the evidence and apply least-privilege principles."


def get_tactic(mitre_id: str) -> str:
    tech = get_technique(mitre_id)
    return tech.get("tactic", "Unknown") if tech else "Unknown"


def get_technique_name(mitre_id: str) -> str:
    tech = get_technique(mitre_id)
    return tech.get("name", mitre_id) if tech else mitre_id


def all_techniques() -> list[dict]:
    return sorted(TECHNIQUES.values(), key=lambda t: t["id"])


def categories() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for t in TECHNIQUES.values():
        out.setdefault(t["tactic"], []).append(t)
    return out
