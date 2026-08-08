"""Threat-intel service: DB-cached indicator lookups + alert IOC extraction."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import THREAT_INTEL_CACHE_HOURS, THREAT_INTEL_ENABLED
from backend.database.models import ThreatIntelRecord
from backend.threatintel import (
    _EMBEDDED_IOCS,
    _abuseipdb,
    _otx,
    _vt,
    _DOMAIN_RE,
    _HASH_RE,
    _IPV4_RE,
    classify_indicator,
)

logger = logging.getLogger("sentinel.threatintel")

_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_URL_DOMAIN_RE = re.compile(r"\b(?:https?://)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9]?\.)+[a-z]{2,})(?:[/:\s]|$)", re.IGNORECASE)
_HASH_RE_64 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

#: Suffixes that are almost never real domains - file names, source paths and
#: arbitrary words get picked up by the loose URL pattern and must be dropped
#: before they pollute the indicator list.
_DOMAIN_DENYLIST = re.compile(
    r"\.(exe|dll|py|pyc|js|ts|json|xml|ini|cfg|txt|log|csv|html|htm|bin|sys|tmp|"
    r"png|jpg|jpeg|ico|svg|gif|zip|rar|7z|msi|bat|cmd|ps|ps1|tmp|c|h|o|min|map|"
    r"tsx|jsx|sln|csproj|pdb|dmp|dat|db|sqlite|so|dylib|main|app|local|localhost|"
    r"server|home|default|internal|host|netlocal|lan|workgroup|smb|self|node)$",
    re.IGNORECASE,
)


def extract_indicators(text: str, limit: int = 12) -> list[str]:
    """Pull IP / domain / hash candidates out of an alert evidence string."""
    if not text:
        return []
    seen: list[str] = []
    for raw in _IP_RE.findall(text) + [m for m in _URL_DOMAIN_RE.findall(text)] + _HASH_RE_64.findall(text):
        indicator = raw.strip(" .(),;'\"")
        if not indicator:
            continue
        if _IPV4_RE.match(indicator) or _HASH_RE.match(indicator):
            if indicator not in seen:
                seen.append(indicator)
        elif _DOMAIN_RE.match(indicator) and not _DOMAIN_DENYLIST.search(indicator):
            if indicator not in seen:
                seen.append(indicator)
        if len(seen) >= limit:
            break
    return seen


def lookup_indicator(db: Session, indicator: str, refresh: bool = False,
                     offline: bool = False) -> dict[str, Any]:
    """Return a full threat-intel verdict for one indicator.

    Order: DB cache -> embedded IOC baseline -> offline classifier -> online
    providers. ``refresh=True`` bypasses the cache and re-queries providers.
    ``offline=True`` skips providers entirely (pipeline fast path; cached or
    classifier verdicts only).
    """
    indicator = indicator.strip().lower()
    result: dict[str, Any] = {
        "indicator": indicator,
        "kind": "ip" if _IPV4_RE.match(indicator) else "domain" if _DOMAIN_RE.match(indicator) else "hash",
        "category": "unknown",
        "label": "No known reputation",
        "confidence": 0.0,
        "sources": [],
        "cached": False,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    if not THREAT_INTEL_ENABLED:
        result["label"] = "Threat intel disabled (SENTINEL_THREAT_INTEL_ENABLED=0)"
        return result

    # 1) Cache
    row = db.scalar(select(ThreatIntelRecord).where(ThreatIntelRecord.indicator == indicator))
    if row and not refresh:
        if row.checked_at and row.checked_at > datetime.now(timezone.utc) - timedelta(hours=THREAT_INTEL_CACHE_HOURS):
            result.update({
                "category": row.category,
                "label": row.label,
                "confidence": row.confidence,
                "sources": row.sources or [],
                "cached": True,
                "checked_at": row.checked_at.isoformat() if row.checked_at else result["checked_at"],
            })
            return result

    # 2) Embedded baseline
    embedded = _EMBEDDED_IOCS.get(indicator)
    if embedded:
        result["category"] = embedded["category"]
        result["label"] = embedded["label"]
        result["confidence"] = 0.95
        result["sources"].append("embedded-ioc")

    # 3) Offline classifier (fills in when embedded is a miss)
    if result["category"] == "unknown":
        offline = classify_indicator(indicator)
        if offline:
            result["category"] = offline["category"]
            result["label"] = offline["label"]
            result["confidence"] = offline.get("confidence", 0.7)
            result["sources"].append("offline-baseline")

    # 4) Online providers (only for missing or non-benign indicators)
    if not offline and result["category"] != "benign":
        for provider in (_abuseipdb, _otx, _vt):
            verdict = provider([indicator]) if provider in (_otx, _vt) else provider(indicator)
            if not verdict:
                continue
            if verdict.get("category") == "malicious" or result["category"] == "unknown":
                result["category"] = verdict.get("category", result["category"])
                result["label"] = verdict.get("label", result["label"])
                result["confidence"] = max(result["confidence"], verdict.get("confidence", 0.6))
            result["sources"].append(provider.__name__.lstrip("_"))
            break

    # Persist cache
    if row is None:
        row = ThreatIntelRecord(indicator=indicator)
        db.add(row)
    row.kind = result["kind"]
    row.category = result["category"]
    row.label = result["label"]
    row.confidence = result["confidence"]
    row.sources = result["sources"]
    row.checked_at = datetime.now(timezone.utc)
    db.commit()

    return result


def enrich_alert(db: Session, alert, refresh: bool = False) -> list[dict[str, Any]]:
    """Enrich all indicators found in an alert's evidence string."""
    evidence = f"{alert.evidence or ''} {alert.name or ''}"
    indicators = extract_indicators(evidence)
    return [lookup_indicator(db, ind, refresh=refresh) for ind in indicators]
