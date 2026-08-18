"""v2 Detection contract (Phase 2).

A detection is a structured, explainable finding produced when telemetry
satisfies a detector's conditions.

    EVENT       Something happened.
    DETECTION   BARAQ determined that something suspicious happened.
    ALERT       A detection that is presented to an analyst.   (later phase)
    INCIDENT    Multiple pieces of evidence form a case.       (later phase)

Phase 2 creates EVENT -> DETECTION only. Nothing here may create alerts,
incidents, risk updates, SOAR actions or ML dependencies.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from backend.detection.evidence import Evidence

#: Allowed severity values (how dangerous IF malicious).
SEVERITIES = ("low", "medium", "high", "critical")

#: Allowed detection lifecycle states (Phase 2 keeps it minimal).
DETECTION_STATUSES = ("new", "expired", "suppressed")


def _clamp_confidence(value: float) -> float:
    """Confidence is 0.0-1.0, rounded to 3 decimals. Never converted to a
    risk score - risk belongs to Phase 6."""
    return round(min(1.0, max(0.0, float(value))), 3)


def make_detection_id(detector_id: str, *parts: str) -> str:
    """Deterministic detection id: ``DET-<detector>-<sha12>``."""
    blob = "|".join(parts)
    digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]
    return f"{detector_id}-{digest}"


@dataclass(frozen=True)
class DETECTION:
    """Canonical detection finding (contract v2.0)."""

    detector_id: str
    detector_version: str

    event_id: str
    event_ids: tuple[str, ...]
    timestamp: datetime
    first_seen: datetime
    last_seen: datetime

    event_type: str

    host_id: str = ""
    host_name: str = ""
    user_id: str = ""
    username: str = ""
    source_ip: str = ""
    destination_ip: str = ""

    title: str = ""
    description: str = ""

    severity: str = "medium"
    confidence: float = 0.5

    mitre_tactic: str = ""
    mitre_technique: str = ""

    evidence: tuple[Evidence, ...] = ()
    observables: tuple[dict[str, Any], ...] = ()

    status: str = "new"

    detection_id: str = ""
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}")
        if self.status not in DETECTION_STATUSES:
            raise ValueError(f"status must be one of {DETECTION_STATUSES}")
        object.__setattr__(self, "confidence", _clamp_confidence(self.confidence))
        object.__setattr__(self, "event_ids", tuple(sorted(set(self.event_ids))))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "observables", tuple(self.observables))
        if not self.detection_id:
            object.__setattr__(
                self,
                "detection_id",
                make_detection_id(self.detector_id, self.event_id, self.title),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "event_id": self.event_id,
            "event_ids": list(self.event_ids),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "event_type": self.event_type,
            "host_id": self.host_id,
            "host_name": self.host_name,
            "user_id": self.user_id,
            "username": self.username,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "evidence": [e.to_dict() for e in self.evidence],
            "observables": [dict(o) for o in self.observables],
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_explain(self) -> str:
        """Explainability block - an analyst must understand the detection
        without opening source code."""
        lines = [
            self.title,
            "-" * 28,
            f"Severity          : {self.severity.upper()}",
            f"Confidence        : {self.confidence:.2f}",
            f"Detector          : {self.detector_id} (v{self.detector_version})",
            f"MITRE             : {self.mitre_technique} - {self.mitre_tactic}",
            "",
            "Why detected",
            "-" * 28,
        ]
        for e in self.evidence:
            lines.append(f"  - {e.field} = {e.value}  ({e.reason})")
        lines += [
            "",
            "Source event(s)",
            "-" * 28,
            f"  - {', '.join(self.event_ids) or self.event_id}",
            "",
            "Affected entity",
            "-" * 28,
            f"  - Host   : {self.host_name or self.host_id or '-'}",
            f"  - User   : {self.username or self.user_id or '-'}",
            f"  - Src IP : {self.source_ip or '-'}",
        ]
        return "\n".join(lines)