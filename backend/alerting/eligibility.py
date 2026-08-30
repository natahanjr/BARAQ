"""Alert eligibility (spec 3.5, 3.6).

A detection does not become an alert merely because a detector fired. An
explicit, detector-aware policy decides. No global ``confidence > 0.7``
blind threshold - each detector has its own semantics:

    D001 External RDP          high severity (contextual: public source)
    D002 Brute Force           medium + 0.60 confidence (window evidence)
    D003 Suspicious PowerShell stricter: high only (plain PS never alerts)
    D004 Python writable path  stricter: medium + 0.70 (historically noisy)
    D005 Ransomware            lower threshold: any behavioral detection
    unknown detector           high + 0.80 (fail closed)
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.alerting.contract import ALERT_SEVERITIES
from backend.detection.contract import DETECTION

_SEVERITY_RANK = {s: i for i, s in enumerate(ALERT_SEVERITIES)}


@dataclass(frozen=True)
class AlertPolicy:
    policy_id: str
    detector_id: str
    min_severity: str
    min_confidence: float
    reason: str


ALERT_POLICIES: dict[str, AlertPolicy] = {
    "D001": AlertPolicy(
        policy_id="ALERT-POLICY-001",
        detector_id="D001",
        min_severity="high",
        min_confidence=0.0,
        reason="High-severity detection with sufficient confidence",
    ),
    "D005": AlertPolicy(
        policy_id="ALERT-POLICY-002",
        detector_id="D005",
        min_severity="medium",
        min_confidence=0.5,
        reason="Behavioral ransomware evidence warrants a lower alert threshold",
    ),
    "D002": AlertPolicy(
        policy_id="ALERT-POLICY-003",
        detector_id="D002",
        min_severity="medium",
        min_confidence=0.6,
        reason="Window-based credential attack evidence meets alert threshold",
    ),
    "D003": AlertPolicy(
        policy_id="ALERT-POLICY-004",
        detector_id="D003",
        min_severity="high",
        min_confidence=0.0,
        reason="Stricter alert threshold for PowerShell behavior",
    ),
    "D004": AlertPolicy(
        policy_id="ALERT-POLICY-005",
        detector_id="D004",
        min_severity="medium",
        min_confidence=0.7,
        reason="Stricter alert threshold for python-on-writable-path",
    ),
}

_DEFAULT_POLICY = AlertPolicy(
    policy_id="ALERT-POLICY-000",
    detector_id="*",
    min_severity="high",
    min_confidence=0.8,
    reason="Unknown detector - fail closed to a strict alert threshold",
)


@dataclass(frozen=True)
class EligibilityResult:
    eligible: bool
    reason: str
    policy_id: str


def policy_for(detector_id: str) -> AlertPolicy:
    return ALERT_POLICIES.get(detector_id, _DEFAULT_POLICY)


def evaluate_detection(detection: DETECTION) -> EligibilityResult:
    """Spec 3.5: does this detection deserve to become an alert?"""
    policy = policy_for(detection.detector_id)
    severity_ok = (
        _SEVERITY_RANK.get(detection.severity, 0) >= _SEVERITY_RANK[policy.min_severity]
    )
    confidence_ok = detection.confidence >= policy.min_confidence
    if severity_ok and confidence_ok:
        return EligibilityResult(
            eligible=True,
            reason=policy.reason,
            policy_id=policy.policy_id,
        )
    return EligibilityResult(
        eligible=False,
        reason=(
            f"Below alert threshold for {policy.policy_id} "
            f"(severity {detection.severity}/{policy.min_severity}, "
            f"confidence {detection.confidence:.3f}/{policy.min_confidence})"
        ),
        policy_id=policy.policy_id,
    )
