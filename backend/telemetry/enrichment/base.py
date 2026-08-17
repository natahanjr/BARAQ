"""v2 enrichment (Phase 1).

Adds context to an EVENT: threat-intel lookup and geo tagging. Every
enrichment is fail-open: on any error it returns the event unchanged and
records the failure in ``facts["enrich_errors"]``. Enrichment never blocks
ingestion and never writes to the database.
"""
from __future__ import annotations

import logging
from dataclasses import replace
from typing import Callable

from backend.telemetry.contract import EVENT

logger = logging.getLogger("baraq.telemetry.enrichment")

#: Mutable facts keys that enrichment may set (documented contract).
_ENRICHMENT_FACTS = ("intel", "geo", "enrich_errors")


def _enrich_intel(event: EVENT, session) -> EVENT:
    """Tag known IOC-ish facts (IPs) against the threat-intel records.

    Read-only: queries only ``threat_intel_records`` via the injected
    session; writes nothing. Missing session -> no-op (still fail-open).
    """
    if session is None:
        return event
    from backend.database.models import ThreatIntelRecord

    ips: list[str] = []
    for key in ("source_ip", "dst_ip", "ip", "destination_ip"):
        value = event.facts.get(key)
        if isinstance(value, str):
            ips.append(value)
    if not ips:
        return event
    try:
        records = session.query(ThreatIntelRecord).all()
        values = set(record.indicator for record in records if record.indicator)
        hits = [ip for ip in ips if ip in values]
        if hits:
            event = replace(event, facts={**event.facts, "intel": {"hits": hits}})
        return event
    except Exception:  # noqa: BLE001 - fail-open
        logger.exception("Intel enrichment failed (fail-open)")
        return event


def _enrich_geo(event: EVENT, session) -> EVENT:
    """Geo-tag source IPs. Deterministic and side-effect free in Phase 1:
    the geo database is a Phase 1+ extension point; record the intent.
    """
    ip = event.facts.get("source_ip") or event.facts.get("ip")
    if not isinstance(ip, str) or not ip:
        return event
    return replace(event, facts={**event.facts, "geo": {"ip": ip, "status": "unresolved"}})


#: Ordered list of enrichment passes (pure, fail-open).
ENRICHERS: list[Callable[[EVENT, object], EVENT]] = [_enrich_geo, _enrich_intel]


def enrich(event: EVENT, session=None) -> EVENT:
    """Run every enrichment pass, fail-open, and collect errors.

    The event object is immutable; each pass returns a copy. If a pass
    raises, the original event is kept and the error is recorded.
    """
    current = event
    errors: list[str] = []
    for enricher in ENRICHERS:
        try:
            current = enricher(current, session)
        except Exception as exc:  # noqa: BLE001 - enrichment must never kill ingestion
            errors.append(f"{getattr(enricher, '__name__', 'enrich')}: {exc}")
            logger.warning("Enrichment pass failed (fail-open): %s", exc)
    if errors:
        current = replace(current, facts={**current.facts, "enrich_errors": errors})
    return current
