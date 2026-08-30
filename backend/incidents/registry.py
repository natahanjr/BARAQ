"""Phase 7 incident eligibility policies I001-I008 (spec 7.3, 7.23, 7.24, 7.28)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyResult:
    policy_id: str
    eligible: bool
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source_type: str = "POLICY"
    source_id: str = ""


def _multi_stage(
    groups: list[dict], findings: list[dict], risks: list[dict]
) -> PolicyResult:
    finding_types = {f.get("correlation_type", "") for f in findings}
    if "MULTI_STAGE" in finding_types and len(groups) >= 1:
        return PolicyResult(
            policy_id="I001",
            eligible=True,
            reason="multi-stage correlation with multiple behavior groups",
            evidence={
                "group_count": len(groups),
                "finding_types": sorted(finding_types),
            },
            source_id=findings[0].get("correlation_id", "") if findings else "",
        )
    return PolicyResult(
        policy_id="I001", eligible=False, reason="insufficient multi-stage evidence"
    )


def _high_risk_with_activity(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    if not risk:
        return PolicyResult(policy_id="I002", eligible=False, reason="no risk context")
    score = float(risk.get("score", 0))
    if score >= 40 and len(groups) >= 1:
        return PolicyResult(
            policy_id="I002",
            eligible=True,
            reason=f"high-risk entity (score {score:.0f}) with supporting activity",
            evidence={"score": score, "group_count": len(groups)},
        )
    return PolicyResult(
        policy_id="I002",
        eligible=False,
        reason=f"risk {score:.0f} below threshold or unsupported",
    )


def _repeated_high_severity(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    high_groups = sum(1 for g in groups if g.get("severity", "").lower() == "high")
    if high_groups >= 1 and len(groups) >= 1:
        return PolicyResult(
            policy_id="I003",
            eligible=True,
            reason="repeated high-severity activity",
            evidence={"high_groups": high_groups, "group_count": len(groups)},
        )
    return PolicyResult(
        policy_id="I003",
        eligible=False,
        reason="insufficient repeated high-severity evidence",
    )


def _lateral_movement(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    techniques = set()
    for g in groups:
        techniques.update(g.get("techniques", []))
    lateral = {t for t in techniques if t.startswith(("T1021", "T1570"))}
    if lateral and len(groups) >= 2:
        return PolicyResult(
            policy_id="I004",
            eligible=True,
            reason="cross-host lateral movement pattern",
            evidence={"techniques": sorted(lateral), "group_count": len(groups)},
        )
    return PolicyResult(
        policy_id="I004", eligible=False, reason="no lateral movement pattern"
    )


def _credential_abuse(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    techniques = set()
    for g in groups:
        techniques.update(g.get("techniques", []))
    cred = {t for t in techniques if t.startswith(("T1110", "T1552"))}
    if cred and len(groups) >= 1:
        return PolicyResult(
            policy_id="I005",
            eligible=True,
            reason="credential abuse pattern",
            evidence={"techniques": sorted(cred)},
        )
    return PolicyResult(
        policy_id="I005", eligible=False, reason="no credential abuse techniques"
    )


def _ransomware(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    techniques = set()
    for g in groups:
        techniques.update(g.get("techniques", []))
    impact = {t for t in techniques if t.startswith(("T1486", "T1490"))}
    if impact:
        return PolicyResult(
            policy_id="I006",
            eligible=True,
            reason="ransomware / impact pattern detected",
            evidence={"techniques": sorted(impact)},
        )
    return PolicyResult(
        policy_id="I006", eligible=False, reason="no ransomware indicators"
    )


def _persistence(
    groups: list[dict], findings: list[dict], risk: dict | None
) -> PolicyResult:
    techniques = set()
    for g in groups:
        techniques.update(g.get("techniques", []))
    persist = {
        t for t in techniques if t.startswith(("T1547", "T1543", "T1136", "T1053"))
    }
    if persist and len(groups) >= 1:
        return PolicyResult(
            policy_id="I007",
            eligible=True,
            reason="persistence pattern detected",
            evidence={"techniques": sorted(persist)},
        )
    return PolicyResult(
        policy_id="I007", eligible=False, reason="no persistence techniques"
    )


def _analyst_escalation(
    groups: list[dict], findings: list[dict], risks: list[dict]
) -> PolicyResult:
    return PolicyResult(
        policy_id="I008",
        eligible=True,
        reason="analyst escalation",
    )


POLICIES: dict[str, Any] = {
    "I001": _multi_stage,
    "I002": _high_risk_with_activity,
    "I003": _repeated_high_severity,
    "I004": _lateral_movement,
    "I005": _credential_abuse,
    "I006": _ransomware,
    "I007": _persistence,
    "I008": _analyst_escalation,
}


def evaluate_policy(policy_id: str, context: dict) -> PolicyResult:
    fn = POLICIES.get(policy_id)
    if fn is None:
        return PolicyResult(
            policy_id=policy_id, eligible=False, reason="unknown policy"
        )
    try:
        return fn(
            context.get("groups", []),
            context.get("findings", []),
            context.get("risk"),
        )
    except Exception as exc:
        return PolicyResult(
            policy_id=policy_id, eligible=False, reason=f"policy error: {exc}"
        )


def list_policies() -> list[dict]:
    return [
        {
            "policy_id": pid,
            "description": fn.__doc__ or pid,
        }
        for pid, fn in POLICIES.items()
    ]
