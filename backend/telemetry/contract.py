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
    """Canonical normalized telemetry event.

    All fields except ``facts`` are primitive and indexable; ``facts`` is a
    free-form mapping of detector-relevant details (command lines, IPs,
    registry paths, ...). ``raw`` carries the original record for audit and
    enrichment provenance (may be None for synthetic events).
    """

    timestamp: datetime
    host: str
    user: str
    source: str
    action: str
    facts: dict[str, Any] = field(default_factory=dict)
    org: str = ""
    raw: Any = None
    integrity: str = "complete"

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
        }
