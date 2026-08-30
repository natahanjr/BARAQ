"""Phase 4 behavioral aggregation (spec 4.1-4.54).

Turns related v2 alerts into explainable behavior groups:

    ALERT
      -> behavior family (detector mapping)
      -> group fingerprint (host + user + source + family)
      -> live group with same fingerprint in window? attach : (close old) create
      -> membership row (reason + score) + evidence + audit

Hard boundaries (4.44/4.45): never creates incidents, never mutates risk,
never executes SOAR/playbooks, no ML. The ONLY tables this package writes
are the four behavior-group tables. Alerts are consumed from ``v2_alerts``
(Phase 3) - raw events are never aggregated directly (spec 4.4).
"""

from __future__ import annotations

from backend.aggregation.contract import (
    BANNED_TITLE_PHRASES as banned_title_phrases,
)
from backend.aggregation.contract import (
    GROUP_STATUSES,
    BehaviorGroup,
    group_title,
)
from backend.aggregation.engine import expire_groups, process_alerts

__all__ = [
    "GROUP_STATUSES",
    "BehaviorGroup",
    "banned_title_phrases",
    "expire_groups",
    "group_title",
    "process_alerts",
]
