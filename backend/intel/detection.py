"""Detection-time threat-intel annotation (P1 item 12).

Alerts are annotated with reputation verdicts WHILE they are created, so
the analyst queue already shows which detections involve known-bad
indicators - no manual on-demand lookups needed. Uses the offline fast
path (DB cache -> embedded IOC baseline -> offline classifier) so the
pipeline never waits on a provider network call; online lookups stay
available on demand in the alert detail view.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

logger = logging.getLogger("baraq.intel.detection")

MAX_INDICATORS = 8


def annotate_alert_intel(db, alert, offline: bool = True) -> dict | None:
    """Look up the alert's indicators and store the verdicts on the alert.

    Returns the payload dict (or None when nothing was found / intel is
    disabled). Never raises: detection must not depend on intel health.
    """
    try:
        from backend.config import THREAT_INTEL_ENABLED
        from backend.threatintel.service import extract_indicators, lookup_indicator

        if not THREAT_INTEL_ENABLED:
            return None

        evidence = f"{alert.evidence or ''} {alert.name or ''}"
        indicators = extract_indicators(evidence, limit=MAX_INDICATORS)
        if not indicators:
            return None

        verdicts = []
        for indicator in indicators:
            try:
                verdict = lookup_indicator(db, indicator, offline=offline)
            except Exception:
                logger.debug("Intel lookup failed for %s", indicator, exc_info=True)
                continue
            if (
                verdict.get("category", "unknown") != "unknown"
                or (verdict.get("confidence") or 0) > 0
            ):
                verdicts.append(verdict)

        if not verdicts:
            return None

        payload = {
            "indicators": verdicts,
            "checked_at": datetime.now(UTC).isoformat(),
            "offline": bool(offline),
        }
        alert.intel_json = json.dumps(payload, default=str)
        try:
            db.flush()
        except Exception:
            # Identity-map conflicts (e.g. the alert was reloaded by _maybe_create_incident's
            # chain reconstruction) can make the UPDATE stale.  Expire the object
            # so the next flush re-loads it from the DB and retries the UPDATE.
            db.expire(alert)
            db.flush()
        return payload
    except Exception:
        logger.exception(
            "Detection-time intel annotation failed for alert #%s",
            getattr(alert, "id", "?"),
        )
        return None


def intel_hits(payload: dict | None) -> int:
    """Count malicious/suspicious indicators in a stored payload."""
    if not payload:
        return 0
    return sum(
        1
        for v in payload.get("indicators", [])
        if v.get("category") in ("malicious", "suspicious")
    )
