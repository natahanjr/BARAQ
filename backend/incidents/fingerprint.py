"""Phase 7 incident fingerprinting (spec 7.4, 7.5)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime


def _normalize(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return json.dumps(sorted(value), separators=(",", ":"))
    if isinstance(value, dict):
        return json.dumps(
            {k: _normalize(v) for k, v in sorted(value.items())}, separators=(",", ":")
        )
    return str(value)


def compute_fingerprint(
    *,
    incident_type: str,
    primary_entity_type: str,
    primary_entity_id: str,
    relevant_entities: list[str],
    correlation_finding_ids: list[str],
    behavior_group_ids: list[str],
    policy_id: str,
) -> str:
    """Deterministic SHA256 fingerprint (spec 7.4).

    Must NOT contain timestamps or random IDs.
    """
    payload = {
        "incident_type": incident_type,
        "primary_entity_type": primary_entity_type,
        "primary_entity_id": primary_entity_id,
        "relevant_entities": sorted(relevant_entities),
        "correlation_finding_ids": sorted(correlation_finding_ids),
        "behavior_group_ids": sorted(behavior_group_ids),
        "policy_id": policy_id,
    }
    normalized = _normalize(payload)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
