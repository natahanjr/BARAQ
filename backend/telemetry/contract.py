"""v2 telemetry EVENT contract (Phase 1).

Defines the canonical ``EVENT`` object per SOC_CONTRACT.md and the
fingerprint used for idempotent ingestion.

    EVENT
    Something happened.
    One normalized record: timestamp, host, user, source, action, facts.

Owned by ``telemetry/``. Nothing in this module may import detection,
correlation, risk or incident code.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class EVENT:
    """Canonical normalized telemetry event (contract v1.1).

    One event structure every telemetry source must produce, so detection
    never needs to understand dozens of raw formats. The core identity
    fields are primitive and indexable; the canonical structured fields
    (``event_type``, ``destination``, ``process``, ``network``, ``outcome``)
    are the detection-facing surface; ``facts`` carries free-form
    detector-relevant extras; ``raw`` preserves the original record for
    audit and enrichment provenance (may be None for synthetic events).
    """

    # --- identity -----------------------------------------------------------
    timestamp: datetime
    host: str
    user: str
    source: str
    action: str
    facts: dict[str, Any] = field(default_factory=dict)
    org: str = ""
    raw: Any = None
    integrity: str = "complete"

    # --- canonical structured fields (contract v1.1) ------------------------
    event_id: str = ""
    event_type: str = ""
    destination: str = ""
    process: dict[str, Any] = field(default_factory=dict)
    network: dict[str, Any] = field(default_factory=dict)
    outcome: str = ""
    schema_version: str = "1.1"

    def fingerprint(self) -> str:
        """Deterministic dedup key: (source, host, action, event-time, facts).

        Two identically-normalized events produce the same fingerprint, so
        replaying the same telemetry never duplicates rows (Phase 0 problem
        RDP_DUPLICATION_001 / BRUTE_FORCE_OVERALERTING_001).
        """
        payload = {
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "action": self.action,
            "ts": int(self.timestamp.timestamp() * 1000),
            "facts": self.facts,
            "org": self.org,
        }
        blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "source": self.source,
            "action": self.action,
            "facts": self.facts,
            "org": self.org,
            "integrity": self.integrity,
            "fingerprint": self.fingerprint(),
            "event_id": self.event_id,
            "event_type": self.event_type,
            "destination": self.destination,
            "process": self.process,
            "network": self.network,
            "outcome": self.outcome,
            "schema_version": self.schema_version,
        }
