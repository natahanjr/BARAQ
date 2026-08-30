"""Phase 7 incident contract (spec 7.1-7.4, 7.7-7.11, 7.15, 7.20, 7.29, 7.33, 7.52)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

INCIDENT_STATES = (
    "NEW",
    "TRIAGED",
    "INVESTIGATING",
    "CONTAINMENT_REQUIRED",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
    "SUPPRESSED",
)

INCIDENT_SEVERITIES = ("critical", "high", "medium", "low")
INCIDENT_PRIORITIES = ("P1", "P2", "P3", "P4")

INCIDENT_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "NEW": ("TRIAGED", "INVESTIGATING", "CLOSED", "SUPPRESSED"),
    "TRIAGED": ("INVESTIGATING", "CONTAINMENT_REQUIRED", "CLOSED", "SUPPRESSED"),
    "INVESTIGATING": (
        "CONTAINMENT_REQUIRED",
        "RESOLVED",
        "CLOSED",
        "SUPPRESSED",
    ),
    "CONTAINMENT_REQUIRED": ("CONTAINED", "INVESTIGATING"),
    "CONTAINED": ("RESOLVED", "CLOSED"),
    "RESOLVED": ("CLOSED",),
    "CLOSED": (),
    "SUPPRESSED": (),
}

BANNED_INCIDENT_PHRASES = (
    "confirmed attack",
    "confirmed breach",
    "attacker confirmed",
    "host compromised",
    "account compromised",
    "malware confirmed",
    "ransomware confirmed",
    "definite compromise",
    "active intrusion",
    "attacker present",
)

AUDIT_ACTIONS = (
    "INCIDENT_CREATED",
    "INCIDENT_UPDATED",
    "INCIDENT_ASSIGNED",
    "INCIDENT_UNASSIGNED",
    "INCIDENT_TEAM_ASSIGNED",
    "INCIDENT_TRIAGED",
    "INCIDENT_INVESTIGATION_STARTED",
    "INCIDENT_CONTAINMENT_STARTED",
    "INCIDENT_CONTAINED",
    "INCIDENT_RESOLVED",
    "INCIDENT_CLOSED",
    "INCIDENT_SUPPRESSED",
    "INCIDENT_REOPEN_REJECTED",
    "INCIDENT_NOTE_ADDED",
    "INCIDENT_EVIDENCE_ADDED",
    "INCIDENT_CREATION_FAILED",
    "INCIDENT_FEEDBACK_ADDED",
)

EVIDENCE_SOURCE_TYPES = (
    "ALERT",
    "BEHAVIOR_GROUP",
    "CORRELATION",
    "RISK",
    "ENTITY",
    "ANALYST",
)

GRAPH_RELATIONSHIP_TYPES = (
    "INCIDENT_HAS_ALERT",
    "INCIDENT_HAS_GROUP",
    "INCIDENT_HAS_CORRELATION",
    "INCIDENT_HAS_RISK",
    "INCIDENT_INVOLVES_ENTITY",
    "INCIDENT_RELATED_TO_INCIDENT",
)

DEFAULT_SLA = {
    "P1": 15,
    "P2": 30,
    "P3": 120,
    "P4": 480,
}


@dataclass(frozen=True)
class IncidentContract:
    incident_id: str
    fingerprint: str
    title: str
    description: str
    status: str
    priority: str
    severity: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None
    primary_entity_type: str
    primary_entity_id: str
    entity_ids: list[str]
    source_type: str
    source_id: str
    incident_version: str
    model_version: str
    created_by: str
    updated_by: str
    assigned_to: str | None
    assigned_team: str | None
    assigned_at: datetime | None
    investigation_state: str | None
    suppression_reason: str | None
    suppression_scope: str | None
    suppression_expires_at: datetime | None
    suppression_created_by: str | None
    policy_id: str | None

    def __post_init__(self) -> None:
        if self.status not in INCIDENT_STATES:
            raise ValueError(f"invalid status {self.status!r}")
        if self.severity not in INCIDENT_SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}")
        if self.priority not in INCIDENT_PRIORITIES:
            raise ValueError(f"invalid priority {self.priority!r}")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0")
        for phrase in BANNED_INCIDENT_PHRASES:
            if phrase in self.title.lower() or phrase in self.description.lower():
                raise ValueError(f"banned incident phrase detected: {phrase!r}")
