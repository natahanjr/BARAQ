"""Threat-intel feed ingestion (roadmap 4.3).

Feed subscriptions are configured with ``BARAQ_THREAT_INTEL_FEEDS`` (a JSON
list) and ingested by :func:`refresh_feeds` - called by the scheduler and by
the Celery task ``baraq.intel_refresh`` (``backend.celery_app``). Supported
feed types:

* ``stix`` / ``taxii`` - TAXII 2.1 collection objects (or a plain STIX 2.1
  bundle). Indicator patterns are parsed for IP / domain / file-hash / URL.
* ``misp`` - MISP ``/attributes/restSearch`` export (``to_ids=1``).
* ``csv`` / ``url`` - plain text or comma-separated indicator lists.

Ingested indicators are upserted into the ``threat_intel_records`` cache so
the existing lookup/enrichment path (``backend.threatintel``) picks them up
immediately; per-feed state is kept in ``threat_intel_feed_state``.
"""

from __future__ import annotations

import logging
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import (
    THREAT_INTEL_ENABLED,
    THREAT_INTEL_FEED_MAX_IOCS,
    THREAT_INTEL_FEED_MIN_CONFIDENCE,
    THREAT_INTEL_FEEDS,
    THREAT_INTEL_TIMEOUT,
)
from backend.database.models import ThreatIntelFeedState, ThreatIntelRecord
from backend.threatintel import _DOMAIN_RE, _HASH_RE, _IPV4_RE

logger = logging.getLogger("baraq.intel.feeds")

FEED_TYPES = ("stix", "taxii", "misp", "csv", "url")

#: STIX 2.1 indicator pattern fragments, e.g.
#: ``[ipv4-addr:value = '185.220.101.45']``, ``[domain-name:value = 'x.com']``,
#: ``[file:hashes.SHA-256 = 'abc...']``, ``[url:value = 'http://...']``.
_STIX_PATTERN_RE = re.compile(
    r"\[(ipv4-addr|domain-name|file|url):"
    r"(?:hashes\.'(?P<hash_algo>[A-Z0-9-]+)'|hashes\.(?P<hash_algo2>[A-Z0-9-]+)|value)"
    r"\s*=\s*'(?P<value>[^']+)'\]",
    re.IGNORECASE,
)

_MISP_TYPE_KIND = {
    "ip-src": "ip",
    "ip-dst": "ip",
    "ip-src|port": "ip",
    "ip-dst|port": "ip",
    "domain": "domain",
    "hostname": "domain",
    "domain|ip": "domain",
    "url": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "sha512": "hash",
    "filename|md5": "hash",
    "filename|sha1": "hash",
    "filename|sha256": "hash",
}

_CSV_IGNORE = re.compile(r"^\s*(#|;|//)")

_DEFAULT_CONFIDENCE = 0.8


@dataclass
class FeedSubscription:
    """One configured feed source."""

    name: str
    feed_type: str
    url: str = ""
    api_key: str = ""
    collection_id: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_config(cls, entry: dict) -> FeedSubscription:
        feed_type = str(entry.get("type", "")).lower()
        if feed_type not in FEED_TYPES:
            raise ValueError(f"unknown feed type {feed_type!r} (expected {FEED_TYPES})")
        return cls(
            name=str(entry.get("name") or entry.get("url") or "feed").strip(),
            feed_type=feed_type,
            url=str(entry.get("url", "")).rstrip("/"),
            api_key=str(entry.get("api_key", "")),
            collection_id=str(entry.get("collection_id", "")),
            headers=dict(entry.get("headers") or {}),
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.feed_type,
            "url": self.url,
            "collection_id": self.collection_id,
            "has_api_key": bool(self.api_key),
        }


def _subscriptions() -> list[FeedSubscription]:
    subs: list[FeedSubscription] = []
    for entry in THREAT_INTEL_FEEDS:
        try:
            subs.append(FeedSubscription.from_config(entry))
        except ValueError as exc:
            logger.warning("Skipping invalid feed entry %r: %s", entry, exc)
    return subs


# ---------------------------------------------------------------------------
# Parsers (pure functions - unit-testable without network)
# ---------------------------------------------------------------------------
def parse_stix_pattern(pattern: str) -> list[tuple[str, str, str]]:
    """Extract (kind, value, hash_algo) from a STIX 2.1 indicator pattern.

    Handles AND/OR compositions by scanning every object fragment.
    """
    found: list[tuple[str, str, str]] = []
    for m in _STIX_PATTERN_RE.finditer(pattern):
        obj_type = m.group(1).lower()
        value = m.group("value").strip()
        if not value:
            continue
        if obj_type == "ipv4-addr":
            kind = "ip"
        elif obj_type == "domain-name":
            kind = "domain"
        elif obj_type == "file":
            algo = (m.group("hash_algo") or m.group("hash_algo2") or "").upper()
            if algo == "SHA-256" or algo == "SHA-1" or algo == "MD5":
                kind = "hash"
            else:
                continue
            found.append((kind, value, algo))
            continue
        elif obj_type == "url":
            kind = "domain"  # stored as domain; the URL host is what we match
            host = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE).split("/")[0]
            value = host
        else:
            continue
        if _IPV4_RE.match(value) or _DOMAIN_RE.match(value):
            found.append((kind, value, ""))
    return found


def _valid_indicator(kind: str, value: str) -> bool:
    value = value.strip().lower()
    if kind == "ip":
        return bool(_IPV4_RE.match(value))
    if kind == "domain":
        return bool(_DOMAIN_RE.match(value)) and "://" not in value
    if kind == "hash":
        return bool(_HASH_RE.match(value))
    return False


def _misp_attributes(data: dict) -> list[tuple[str, str, str, float]]:
    """Flatten a MISP restSearch response to (kind, value, category, confidence).

    ``to_ids=1`` attributes are treated as known-bad with default confidence;
    tags are ignored for scoring (we keep the per-attribute category as the
    label source instead).
    """
    out: list[tuple[str, str, str, float]] = []
    attrs = (data.get("response") or {}).get("Attribute") or []
    for attr in attrs:
        value = str(attr.get("value", "")).strip()
        kind = _MISP_TYPE_KIND.get(str(attr.get("type", "")).lower())
        if not kind or not value:
            continue
        if kind == "domain":
            value = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE).split("/")[0]
        if not _valid_indicator(kind, value):
            continue
        category = str(attr.get("category") or "Unknown").strip() or "MISP feed"
        out.append((kind, value, category, _DEFAULT_CONFIDENCE))
    return out


# ---------------------------------------------------------------------------
# Fetching (network; isolated behind _fetch_url for tests)
# ---------------------------------------------------------------------------
def _fetch_url(
    url: str, headers: dict[str, str] | None = None, timeout: float | None = None
) -> str | None:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(
            req, timeout=timeout or THREAT_INTEL_TIMEOUT
        ) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.warning("Feed fetch failed for %s: %s", url, exc)
        return None


def _stix_objects(raw: str) -> list[dict]:
    import json

    data = json.loads(raw)
    return data.get("objects") or []


def _fetch_taxii(sub: FeedSubscription) -> list[tuple[str, str, str, float]]:
    """Fetch STIX 2.1 indicator objects from a TAXII collection or bundle URL."""
    headers = {"Accept": "application/taxii+json;version=2.1", **sub.headers}
    if sub.api_key:
        headers.setdefault("Authorization", f"Bearer {sub.api_key}")

    objects_url = sub.url
    if sub.feed_type == "taxii":
        collection_id = sub.collection_id
        if not collection_id:
            raw = _fetch_url(f"{sub.url}/collections", headers)
            if not raw:
                return []
            import json

            try:
                collections = json.loads(raw).get("collections") or []
            except ValueError:
                return []
            if not collections:
                return []
            collection_id = str(collections[0].get("id", ""))
            if not collection_id:
                return []
        objects_url = f"{sub.url}/collections/{collection_id}/objects?limit={THREAT_INTEL_FEED_MAX_IOCS}"

    raw = _fetch_url(objects_url, headers)
    if not raw:
        return []
    try:
        objects = _stix_objects(raw)
    except ValueError:
        logger.warning("Feed %s: response is not STIX JSON", sub.name)
        return []

    results: list[tuple[str, str, str, float]] = []
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = str(obj.get("pattern") or "")
        for kind, value, _algo in parse_stix_pattern(pattern):
            if not _valid_indicator(kind, value):
                continue
            label = str(
                obj.get("name") or obj.get("description") or "STIX indicator"
            ).strip()
            try:
                confidence = min(
                    0.99, float(obj.get("confidence") or _DEFAULT_CONFIDENCE) / 100.0
                )
            except (TypeError, ValueError):
                confidence = _DEFAULT_CONFIDENCE
            results.append((kind, value, label, confidence))
    return results


def _fetch_misp(sub: FeedSubscription) -> list[tuple[str, str, str, float]]:
    """Fetch to_ids attributes from a MISP instance."""
    headers = {"Accept": "application/json", **sub.headers}
    if sub.api_key:
        headers.setdefault("Authorization", sub.api_key)
    url = (
        f"{sub.url}/attributes/restSearch?returnFormat=json&to_ids=1"
        f"&page=1&limit={THREAT_INTEL_FEED_MAX_IOCS}"
    )
    raw = _fetch_url(url, headers)
    if not raw:
        return []
    try:
        import json

        data = json.loads(raw)
    except ValueError:
        logger.warning("Feed %s: response is not MISP JSON", sub.name)
        return []
    return _misp_attributes(data)


def _fetch_plain(sub: FeedSubscription) -> list[tuple[str, str, str, float]]:
    """Fetch a plain text / CSV indicator list (one IOC per line)."""
    headers = {"Accept": "text/plain", **sub.headers}
    raw = _fetch_url(sub.url, headers)
    if not raw:
        return []
    results: list[tuple[str, str, str, float]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or _CSV_IGNORE.match(line):
            continue
        value = line.split(",")[0].strip()
        kind = (
            "ip"
            if _IPV4_RE.match(value)
            else "domain" if _DOMAIN_RE.match(value) else "hash"
        )
        if _valid_indicator(kind, value):
            results.append((kind, value, sub.name, _DEFAULT_CONFIDENCE))
    return results


def fetch_feed(sub: FeedSubscription) -> list[tuple[str, str, str, float]]:
    """Fetch and parse one subscription; returns (kind, value, label, confidence)."""
    if sub.feed_type in ("stix", "taxii"):
        return _fetch_taxii(sub)
    if sub.feed_type == "misp":
        return _fetch_misp(sub)
    return _fetch_plain(sub)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
def _upsert_iocs(
    db: Session, sub: FeedSubscription, iocs: list[tuple[str, str, str, float]]
) -> dict:
    """Upsert feed IOCs into the threat-intel cache; never downgrades a record.

    Returns {"inserted": n, "updated": m, "iocs": total}.
    """
    inserted = updated = 0
    source = f"{sub.feed_type}:{sub.name}"
    for kind, value, label, confidence in iocs:
        value = value.strip().lower()
        row = db.scalar(
            select(ThreatIntelRecord).where(ThreatIntelRecord.indicator == value)
        )
        if row is None:
            db.add(
                ThreatIntelRecord(
                    indicator=value,
                    kind=kind,
                    category="malicious",
                    label=(label or "Threat-intel feed IOC")[:400],
                    confidence=confidence,
                    sources=[source],
                )
            )
            inserted += 1
        else:
            if confidence > (row.confidence or 0.0):
                row.confidence = confidence
            if row.category != "malicious":
                row.category = "malicious"
            row.kind = kind
            row.label = (label or row.label or "Threat-intel feed IOC")[:400]
            sources = set(row.sources or [])
            sources.add(source)
            row.sources = sorted(sources)
            updated += 1
    db.commit()
    return {"inserted": inserted, "updated": updated, "iocs": len(iocs)}


def refresh_feeds(db: Session) -> dict:
    """Refresh every configured subscription and return a per-feed summary."""
    if not THREAT_INTEL_ENABLED:
        return {"enabled": False, "feeds": []}
    subs = _subscriptions()
    summaries: list[dict] = []
    for sub in subs:
        state = db.scalar(
            select(ThreatIntelFeedState).where(ThreatIntelFeedState.name == sub.name)
        )
        if state is None:
            state = ThreatIntelFeedState(
                name=sub.name, feed_type=sub.feed_type, url=sub.url
            )
            db.add(state)
        try:
            iocs = fetch_feed(sub)
            if not iocs:
                raise ValueError("feed returned no indicators")
            result = _upsert_iocs(db, sub, iocs[:THREAT_INTEL_FEED_MAX_IOCS])
            state.feed_type = sub.feed_type
            state.url = sub.url
            state.last_success_at = datetime.now(UTC)
            state.last_error = ""
            state.ioc_count = result["iocs"]
            state.total_fetched += result["iocs"]
            db.commit()
            summaries.append(
                {
                    "name": sub.name,
                    "type": sub.feed_type,
                    "status": "ok",
                    **result,
                }
            )
            logger.info("Intel feed %s: %s", sub.name, result)
        except Exception as exc:
            db.rollback()
            db.add(state)
            state.last_error = str(exc)[:500]
            db.commit()
            summaries.append(
                {
                    "name": sub.name,
                    "type": sub.feed_type,
                    "status": "error",
                    "error": str(exc),
                }
            )
            logger.warning("Intel feed %s failed: %s", sub.name, exc)
    return {"enabled": True, "feeds": summaries}


def feed_states(db: Session) -> list[dict]:
    """Current feed subscription state (for the API)."""
    states = {s.name: s for s in db.scalars(select(ThreatIntelFeedState)).all()}
    out: list[dict] = []
    for sub in _subscriptions():
        entry = sub.to_dict()
        entry["state"] = states[sub.name].to_dict() if sub.name in states else None
        out.append(entry)
    return out


def match_text(db: Session, text: str, limit: int = 25) -> list[dict]:
    """Match free text against the DB threat-intel cache (IOC matching).

    Only records with category ``malicious``/``suspicious`` at or above
    ``BARAQ_THREAT_INTEL_FEED_MIN_CONFIDENCE`` count as matches.
    """
    from backend.threatintel.service import extract_indicators

    indicators = extract_indicators(text, limit=limit)
    if not indicators:
        return []
    rows = db.scalars(
        select(ThreatIntelRecord).where(
            ThreatIntelRecord.indicator.in_(indicators),
            ThreatIntelRecord.category.in_(("malicious", "suspicious")),
            ThreatIntelRecord.confidence >= THREAT_INTEL_FEED_MIN_CONFIDENCE,
        )
    ).all()
    return [row.to_dict() for row in rows]
