"""Phase 4 group fingerprint (spec 4.7).

    group_fingerprint = SHA256(primary_host + primary_user +
                               normalized_source + behavior_family)

Exact serialization (documented in docs/phase4/GROUPING_POLICY.md):

    sha256_hex(json.dumps({
        "primary_host":  host_name or host_id or "none",
        "primary_user":  username or user_id or "none",
        "normalized_source": source_ip or "none",
        "behavior_family": family,
    }, sort_keys=True))

Never a random UUID as the grouping key - the UUID-free guarantee is tested.
"""
from __future__ import annotations

import hashlib
import json
from typing import Protocol


class GroupableAlert(Protocol):
    host_id: str
    host_name: str
    user_id: str
    username: str
    source_ip: str


def primary_host(alert: GroupableAlert) -> str:
    return (alert.host_name or alert.host_id or "none").strip().lower() or "none"


def primary_user(alert: GroupableAlert) -> str:
    return (alert.username or alert.user_id or "none").strip().lower() or "none"


def normalized_source(alert: GroupableAlert) -> str:
    # "Normalized" = the source_ip as-is (IPs need no casing folding), with
    # the empty/missing case collapsed to a stable "none".
    return (alert.source_ip or "none").strip().lower() or "none"


def group_fingerprint(alert: GroupableAlert, behavior_family: str) -> str:
    identity = {
        "primary_host": primary_host(alert),
        "primary_user": primary_user(alert),
        "normalized_source": normalized_source(alert),
        "behavior_family": behavior_family,
    }
    payload = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
