"""Phase 4 grouping policies (spec 4.9-4.12, 4.19, 4.36, 4.37).

Behavioral identity wins over alert titles (4.8): families come from the
detector mapping in config, not from MITRE alone (4.26). Grouping is
identity-based (host + user + source + family) and never cross-host or
cross-user by default (4.36/4.37) - those relationships belong to Phase 5.
"""
from __future__ import annotations

from typing import Protocol

import backend.config as config
from backend.aggregation.contract import BEHAVIOR_FAMILIES

from .fingerprint import GroupableAlert, group_fingerprint


def behavior_family(alert: GroupableAlert, detector_id: str | None = None) -> str:
    """Detector -> behavior family (spec 4.9). Unknown detectors fail closed."""
    key = detector_id or getattr(alert, "detector_id", "") or ""
    family = config.DETECTOR_BEHAVIOR_FAMILIES.get(key)
    if family is None:
        return config.BEHAVIOR_FAMILY_DEFAULT
    return family if family in BEHAVIOR_FAMILIES else config.BEHAVIOR_FAMILY_DEFAULT


def window_minutes(family: str) -> int:
    return config.AGGREGATION_WINDOWS_MINUTES.get(
        family, config.AGGREGATION_WINDOW_DEFAULT_MINUTES
    )


def minimum_relationships(family: str) -> int:
    """Contextual relationships required to group (spec 4.19).

    Fingerprint equality guarantees host + user + source + family shared -
    that is 4 shared relationships, always >= the floor of 2. Unknown
    families additionally fail closed: they only ever group on a full
    identity match.
    """
    if family == "unknown":
        return 4
    return config.AGGREGATION_MIN_RELATIONSHIPS


def membership_score(alert: GroupableAlert, family: str) -> float:
    """Grouping score (spec 4.18) - host +0.40, user +0.25, source +0.20,
    time proximity +0.15 = 1.00. A grouping score, never a risk score.

    Membership is only ever offered on full fingerprint equality, so all
    three identity factors apply; the time factor applies because the alert
    was checked against the group's window.
    """
    w = config.AGGREGATION_MEMBERSHIP_WEIGHTS
    base = w["host"] + w["user"] + w["source"]
    if family == "unknown":
        return min(1.0, base + w["time"])
    return min(1.0, base + w["time"])


def membership_reason(alert: GroupableAlert, family: str, window: int) -> str:
    parts = [
        f"same host ({primary_host_of(alert)})",
        f"same user ({primary_user_of(alert)})",
        f"same source ({source_of(alert)})",
        f"same behavior family ({family})",
        f"within {window}-minute aggregation window",
    ]
    return " + ".join(parts)


def fingerprint_for(alert: GroupableAlert, detector_id: str | None = None) -> str:
    family = behavior_family(alert, detector_id)
    return group_fingerprint(alert, family)


def primary_host_of(alert: GroupableAlert) -> str:
    from .fingerprint import primary_host

    return primary_host(alert)


def primary_user_of(alert: GroupableAlert) -> str:
    from .fingerprint import primary_user

    return primary_user(alert)


def source_of(alert: GroupableAlert) -> str:
    from .fingerprint import normalized_source

    return normalized_source(alert)