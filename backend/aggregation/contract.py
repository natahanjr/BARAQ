"""Phase 4 behavior group contract (spec 4.2, 4.21, 4.27, 4.35).

A behavior group is a container for related alerts. It is NOT an incident,
NOT an attack chain and NOT a risk verdict (spec 4.1, 4.35): titles are
behavioral, confidence is a deterministic grouping confidence, and the
group never escalates severity (4.28).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

GROUP_STATUSES = ("ACTIVE", "QUIET", "CLOSED")

#: Severity is never escalated by aggregation (spec 4.28): the group only
#: reports its highest member severity.
GROUP_SEVERITIES = ("low", "medium", "high", "critical")

#: Behavior families (spec 4.9). ``unknown`` fails closed: alerts from
#: detectors without a family mapping only group with a full identity match.
BEHAVIOR_FAMILIES = ("authentication", "execution", "encryption", "unknown")

#: Titles must summarize behavior without overclaiming (spec 4.21, 4.35).
FAMILY_TITLES = {
    "authentication": "Remote Authentication Activity",
    "execution": "Suspicious Execution Activity",
    "encryption": "Potential Data Encryption Activity",
    "unknown": "Suspicious Activity",
}

#: Phrases that would claim more evidence than Phase 4 has (spec 4.21, 4.35).
#: The engine titles never contain them, and the contract rejects them.
BANNED_TITLE_PHRASES = (
    "confirmed",
    "attack",
    "compromised",
    "compromise",
    "intrusion",
    "breach",
    "proves",
    "exfiltration",
    "ransomware attack",
)

#: Observables aggregated per group (spec 4.24).
OBSERVABLE_KEYS = (
    "hosts",
    "users",
    "source_ips",
    "destination_ips",
    "processes",
    "file_paths",
    "domains",
)


def group_title(family: str) -> str:
    return FAMILY_TITLES.get(family, FAMILY_TITLES["unknown"])


@dataclass
class BehaviorGroup:
    """Behavioral episode container (spec 4.2).

    Independent of any risk/incident meaning. ``highest_severity`` is the
    strongest member severity - aggregation never invents a stronger one.
    """

    behavior_group_id: str
    group_fingerprint: str
    title: str
    description: str
    status: str = "ACTIVE"
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    alert_count: int = 0
    occurrence_count: int = 0
    alert_ids: list[str] = field(default_factory=list)
    host_ids: list[str] = field(default_factory=list)
    user_ids: list[str] = field(default_factory=list)
    source_ips: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    observables: dict = field(default_factory=dict)
    confidence: float = 0.0
    highest_severity: str = "low"
    created_at: datetime | None = None
    updated_at: datetime | None = None
    closed_at: datetime | None = None

    def __post_init__(self) -> None:
        if not self.behavior_group_id.startswith("BG-"):
            raise ValueError(f"behavior_group_id must look like BG-000001, got {self.behavior_group_id!r}")
        if self.status not in GROUP_STATUSES:
            raise ValueError(f"invalid group status {self.status!r}")
        if self.highest_severity not in GROUP_SEVERITIES:
            raise ValueError(f"invalid highest_severity {self.highest_severity!r}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"group confidence must be within 0.000-1.000, got {self.confidence}")
        lower = self.title.lower()
        if any(phrase in lower for phrase in BANNED_TITLE_PHRASES):
            raise ValueError(
                f"group title overclaims evidence (banned phrase): {self.title!r}"
            )

    def to_dict(self) -> dict:
        return {
            "behavior_group_id": self.behavior_group_id,
            "group_fingerprint": self.group_fingerprint,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "alert_count": self.alert_count,
            "occurrence_count": self.occurrence_count,
            "alert_ids": list(self.alert_ids),
            "host_ids": list(self.host_ids),
            "user_ids": list(self.user_ids),
            "source_ips": list(self.source_ips),
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
            "observables": dict(self.observables),
            "confidence": self.confidence,
            "highest_severity": self.highest_severity,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }
