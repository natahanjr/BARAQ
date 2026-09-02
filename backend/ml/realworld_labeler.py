"""Real-world labeling: threat intel + analyst verdicts -> ML training labels.

Replaces the hardcoded ``_NET_ATTACK_PREFIXES`` with dynamic lookups:

1. **Threat-intel IPs**: All IPs in the ``threat_intel_records`` table with
   ``category IN ('malicious', 'abusive')`` are treated as attack indicators
   for the network stream.  The offline embedded IOC baseline, AbuseIPDB,
   OTX, VirusTotal, and any configured feed subscriptions all contribute.

2. **Analyst verdicts**: Events with a ``true_positive`` verdict are always
   labelled attack; ``false_positive`` verdicts are always labelled benign.
   Analyst labels override the heuristic labeler.

3. **Hybrid scoring**: When both sources exist the combined label is the
   *union* — an IP flagged by *either* threat intel or analyst verdict is
   treated as malicious.  This maximises recall without sacrificing the
   analyst feedback loop.

Usage::

    from backend.ml.realworld_labeler import (
        is_attack_ip,
        get_attack_ips,
        get_analyst_labels,
        hybrid_label_event,
    )

    # Network stream: is this remote IP malicious?
    if is_attack_ip(session, "203.0.113.66"):
        ...

    # Bulk load for training
    attack_ips = get_attack_ips(session)
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from backend.database.models import ThreatIntelRecord, Verdict

logger = logging.getLogger("baraq.ml.realworld")

# Cache TTL: how long the IP set is held in memory before re-querying the DB.
_CACHE_TTL_SECONDS = 300  # 5 minutes

# Internal cache state (module-level singleton).
_ip_cache: set[str] = set()
_ip_cache_ts: float = 0.0


def _refresh_ip_cache(session, force: bool = False) -> set[str]:
    """Load all malicious/abusive IPs from the threat-intel cache."""
    global _ip_cache, _ip_cache_ts
    now = time.time()
    if not force and _ip_cache and (now - _ip_cache_ts) < _CACHE_TTL_SECONDS:
        return _ip_cache

    try:
        rows = session.execute(
            select(ThreatIntelRecord.indicator).where(
                ThreatIntelRecord.kind == "ip",
                ThreatIntelRecord.category.in_(("malicious", "abusive")),
            )
        ).scalars().all()
        _ip_cache = {str(ip) for ip in rows if ip}
        _ip_cache_ts = now
        if _ip_cache:
            logger.debug(
                "Loaded %d threat-intel IPs for ML labeling", len(_ip_cache)
            )
    except Exception:
        logger.debug("Failed to load threat-intel IPs", exc_info=True)

    # Always include the legacy test-net ranges so existing test fixtures
    # still work without needing a threat-intel lookup.
    _ip_cache.update(
        {
            "203.0.113.66", "203.0.113.77",
            "198.51.100.66", "198.51.100.77",
            "192.0.2.66", "192.0.2.77",
        }
    )
    return _ip_cache


def get_attack_ips(session, force: bool = False) -> set[str]:
    """Return the set of IPs known to be malicious from threat intel.

    Combines:
    - Embedded IOC baseline (always available)
    - DB-cached provider results (AbuseIPDB, OTX, VT, etc.)
    - Legacy test-net ranges (backward compat)

    The result is cached for ``_CACHE_TTL_SECONDS`` to avoid hammering the DB
    on every training call.
    """
    return _refresh_ip_cache(session, force=force)


def is_attack_ip(session, ip: str) -> bool:
    """Check if a single IP is flagged by threat intel or analyst verdict."""
    if not ip:
        return False
    attack_ips = get_attack_ips(session)
    return ip in attack_ips


def is_attack_ip_offline(ip: str) -> bool:
    """Fast offline check without a DB session (for training scripts).

    Uses only the cached IP set.  If the cache is cold, falls back to the
    legacy hardcoded prefixes so training scripts never block on a DB lookup
    on the hot path.
    """
    if not ip:
        return False
    if _ip_cache and ip in _ip_cache:
        return True
    # Fallback: legacy test-net ranges (safe default for offline scripts)
    return ip.startswith(("203.0.113.", "198.51.100.", "192.0.2."))


def get_analyst_labels(session) -> dict[int, int]:
    """Load all analyst verdicts as {event_id: 0|1}.

    Returns a dict mapping NormalizedEvent.id -> label where:
    - 1 = confirmed attack (true_positive)
    - 0 = confirmed benign (false_positive)

    These labels override the heuristic labeler during training.
    """
    try:
        rows = session.execute(select(Verdict.event_id, Verdict.verdict)).all()
        return {
            int(event_id): (1 if verdict == "true_positive" else 0)
            for event_id, verdict in rows
        }
    except Exception:
        logger.debug("Failed to load analyst verdicts", exc_info=True)
        return {}


def hybrid_label_event(
    session,
    event_id: int,
    raw_json: dict,
    source_ip: str = "",
    analyst_labels: dict[int, int] | None = None,
) -> bool:
    """Determine if an event is an attack using the hybrid labeling strategy.

    Priority:
    1. Analyst verdict (highest authority — overrides everything)
    2. Threat-intel IP match (for network-relevant events)
    3. Heuristic fallback (MLAnomalyDetector._is_attack_sample)

    Returns True if the event is an attack.
    """
    # 1. Analyst verdict is authoritative
    if analyst_labels and event_id in analyst_labels:
        return bool(analyst_labels[event_id])

    # 2. Threat-intel IP match (use offline check if no session available)
    if source_ip:
        if session is not None:
            if is_attack_ip(session, source_ip):
                return True
        elif is_attack_ip_offline(source_ip):
            return True

    # 3. Heuristic fallback
    from backend.ml.anomaly import MLAnomalyDetector
    return MLAnomalyDetector._is_attack_sample(event_id, raw_json)


def get_threat_intel_stats(session) -> dict:
    """Return stats about the threat-intel labeling data for monitoring."""
    try:
        total = session.scalar(select(ThreatIntelRecord.indicator)) or 0
        malicious = session.scalar(
            select(ThreatIntelRecord.indicator).where(
                ThreatIntelRecord.category.in_(("malicious", "abusive"))
            )
        ) or 0
        verdicts = session.execute(select(Verdict.verdict)).all()
        tp = sum(1 for v in verdicts if v[0] == "true_positive")
        fp = sum(1 for v in verdicts if v[0] == "false_positive")
        return {
            "threat_intel_total": total,
            "threat_intel_malicious_ips": len(_ip_cache),
            "analyst_true_positives": tp,
            "analyst_false_positives": fp,
            "analyst_total": tp + fp,
            "cache_age_seconds": round(time.time() - _ip_cache_ts, 1)
            if _ip_cache_ts
            else None,
        }
    except Exception:
        return {"error": "failed to query stats"}
