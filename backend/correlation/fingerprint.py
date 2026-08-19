"""Phase 5 correlation fingerprint (spec 5.6).

    finding_fingerprint = SHA256(correlation_type + sorted member ids +
                                 normalized edges)

Exact serialization (documented in docs/phase5/CORRELATION_CONTRACT.md):

    sha256_hex(json.dumps({
        "correlation_type": type,
        "member_group_ids": sorted member ids,
        "edges": sorted normalized edges,
    }, sort_keys=True))

Each edge normalizes to (source_group_id, target_group_id,
relationship_type). Deterministic: the same member sequence with the same
edges always yields the same fingerprint - the UUID-free guarantee is
tested (spec 5.6, 5.7).
"""
from __future__ import annotations

import hashlib
import json


def _normalize_edges(edges: list[dict]) -> list[dict]:
    normalized = []
    for edge in edges or []:
        normalized.append(
            {
                "source_group_id": edge.get("source_group_id", ""),
                "target_group_id": edge.get("target_group_id", ""),
                "relationship_type": edge.get("relationship_type", ""),
            }
        )
    return sorted(normalized, key=lambda e: json.dumps(e, sort_keys=True))


def finding_fingerprint(
    correlation_type: str,
    member_group_ids: list[str],
    edges: list[dict] | None = None,
) -> str:
    payload = {
        "correlation_type": correlation_type,
        "member_group_ids": sorted(member_group_ids),
        "edges": _normalize_edges(edges),
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
