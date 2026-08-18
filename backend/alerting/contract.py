"""Alert contract (Phase 3, spec 3.1-3.4).

An ALERT is the analyst-facing surfacing of a validated DETECTION:

    Detection  = BARAQ recognized suspicious behavior
    Alert      = BARAQ decided the detection should be surfaced to an analyst
    Incident   = Phase 7 - multiple pieces of evidence form a security case

Alerts always retain a reference to their originating detection(s) and the
full evidence chain. Alert-level severity and confidence inherit from the
detection (spec 3.18/3.19) - never derived from occurrence counts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

ALERT_SEVERITIES = ("low", "medium", "high", "critical")

ALERT_STATUSES = (
    "OPEN",
    "ACKNOWLEDGED",
    "IN_PROGRESS",
    "RESOLVED",
    "CLOSED",
    "SUPPRESSED",
)

FEEDBACK_TYPES = (
    "TRUE_POSITIVE",
    "FALSE_POSITIVE",
    "BENIGN",
    "DUPLICATE",
    "EXPECTED_ACTIVITY",
    "UNKNOWN",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class ALERT:
    """Analyst-facing alert (spec 3.3). Immutable value object."""

    alert_id: str
    detection_id: str
    detection_ids: tuple[str, ...] = ()
    alert_fingerprint: str = ""

    title: str = ""
    description: str = ""

    severity: str = "medium"
    confidence: float = 0.0

    status: str = "OPEN"

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    occurrence_count: int = 1

    host_id: str = ""
    host_name: str = ""
    user_id: str = ""
    username: str = ""
    source_ip: str = ""
    destination_ip: str = ""

    mitre_tactic: str = ""
    mitre_technique: str = ""

    evidence: tuple[dict, ...] = ()
    observables: tuple[dict, ...] = ()

    detector_id: str = ""
    detector_version: str = ""

    created_at: datetime = field(default_factory=utcnow)
    updated_at: datetime = field(default_factory=utcnow)

    assigned_to: str | None = None
    assigned_at: datetime | None = None
    acknowledged_at: datetime | None = None
    acknowledged_by: str | None = None
    resolved_at: datetime | None = None
    feedback: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {ALERT_SEVERITIES}")
        if self.status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in 0.0-1.0")
        if self.feedback is not None and self.feedback not in FEEDBACK_TYPES:
            raise ValueError(f"feedback must be one of {FEEDBACK_TYPES}")

    def to_dict(self) -> dict:
        """Plain JSON-safe dict for API responses."""
        return {
            "alert_id": self.alert_id,
            "detection_id": self.detection_id,
            "detection_ids": list(self.detection_ids),
            "alert_fingerprint": self.alert_fingerprint,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "occurrence_count": self.occurrence_count,
            "host_id": self.host_id,
            "host_name": self.host_name,
            "user_id": self.user_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": list(self.evidence),
            "observables": list(self.observables),
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "feedback": self.feedback,
        }