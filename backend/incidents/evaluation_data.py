"""Phase 7 incident evaluation corpus (spec 7.40)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

EVAL_T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)


def _group(
    group_id: str,
    hosts: list[str],
    techniques: list[str],
    severity: str = "high",
    alert_count: int = 10,
    first_seen: datetime = EVAL_T0,
    last_seen: datetime = EVAL_T0,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    destination_ips: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": hosts,
        "users": users or [],
        "source_ips": source_ips or [],
        "destination_ips": destination_ips or [],
        "techniques": techniques,
        "tactics": [],
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "external_source": False,
    }


def _finding(
    finding_id: str,
    hosts: list[str],
    correlation_type: str = "MULTI_STAGE",
    first_seen: datetime = EVAL_T0,
    last_seen: datetime = EVAL_T0,
    users: list[str] | None = None,
    source_ips: list[str] | None = None,
    confidence: float = 0.9,
) -> dict[str, Any]:
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": correlation_type,
        "hosts": hosts,
        "users": users or [],
        "source_ips": source_ips or [],
        "member_group_ids": [],
        "confidence": confidence,
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _risk(
    risk_id: str,
    score: float,
    severity: str = "medium",
    entity_type: str = "HOST",
    entity_id: str = "h1",
) -> dict[str, Any]:
    return {
        "risk_id": risk_id,
        "score": score,
        "severity": severity,
        "entity_type": entity_type,
        "entity_id": entity_id,
    }


SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "INC-001_SINGLE_ALERT_NOT_INCIDENT",
        "description": "One isolated low-severity alert does not create an incident (7.24)",
        "steps": [
            {
                "groups": [
                    _group(
                        "g-inc-001a",
                        ["h-inc-001"],
                        ["T1078"],
                        severity="low",
                        alert_count=1,
                    )
                ],
                "findings": [],
            },
        ],
        "expected": {"incident_created": False},
    },
    {
        "id": "INC-002_REPEATED_ALERT_PATTERN",
        "description": "Repeated high alerts via groups may create an incident (7.25)",
        "steps": [
            {
                "groups": [
                    _group(
                        "g-inc-002a",
                        ["h-inc-002"],
                        ["T1110"],
                        severity="high",
                        alert_count=10,
                    )
                ],
                "findings": [],
                "policy_id": "I003",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I003", "severity": "high"},
    },
    {
        "id": "INC-003_CORRELATED_MULTI_STAGE",
        "description": "Multi-stage correlation with multiple groups creates an incident (7.23)",
        "steps": [
            {
                "groups": [
                    _group("g-inc-003a", ["h-inc-003a"], ["T1133"]),
                    _group("g-inc-003b", ["h-inc-003a"], ["T1021.001"]),
                ],
                "findings": [_finding("CF-inc-003", ["h-inc-003a"])],
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I001", "severity": "high"},
    },
    {
        "id": "INC-004_HIGH_RISK_WITH_ACTIVITY",
        "description": "High-risk entity with supporting groups creates an incident (7.28)",
        "steps": [
            {
                "groups": [_group("g-inc-004a", ["h-inc-004"], ["T1059.001"])],
                "findings": [],
                "risks": [
                    _risk("ER-inc-004", 72.0, severity="high", entity_id="h-inc-004")
                ],
                "policy_id": "I002",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I002", "severity": "high"},
    },
    {
        "id": "INC-005_RANSOMWARE_PATTERN",
        "description": "Ransomware indicators trigger I006 (7.23)",
        "steps": [
            {
                "groups": [_group("g-inc-005a", ["h-inc-005"], ["T1486", "T1490"])],
                "findings": [],
                "policy_id": "I006",
            },
        ],
        "expected": {
            "incident_created": True,
            "policy_id": "I006",
            "severity": "critical",
        },
    },
    {
        "id": "INC-006_LATERAL_MOVEMENT",
        "description": "Cross-host lateral movement creates an incident (7.4)",
        "steps": [
            {
                "groups": [
                    _group("g-inc-006a", ["h-inc-006a"], ["T1021.001"]),
                    _group("g-inc-006b", ["h-inc-006b"], ["T1021.001"]),
                ],
                "findings": [],
                "policy_id": "I004",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I004", "severity": "high"},
    },
    {
        "id": "INC-007_CREDENTIAL_ABUSE",
        "description": "Credential abuse pattern creates an incident (7.23)",
        "steps": [
            {
                "groups": [_group("g-inc-007a", ["h-inc-007"], ["T1110", "T1552"])],
                "findings": [],
                "policy_id": "I005",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I005", "severity": "high"},
    },
    {
        "id": "INC-008_PERSISTENCE_PATTERN",
        "description": "Persistence techniques create an incident (7.23)",
        "steps": [
            {
                "groups": [_group("g-inc-008a", ["h-inc-008"], ["T1547", "T1543"])],
                "findings": [],
                "policy_id": "I007",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I007", "severity": "high"},
    },
    {
        "id": "INC-009_UNRELATED_HOSTS",
        "description": "Unrelated hosts do not merge into one incident (7.26)",
        "steps": [
            {
                "groups": [_group("g-inc-009a", ["h-inc-009a"], ["T1059.001"])],
                "findings": [],
                "policy_id": "I003",
            },
            {
                "groups": [_group("g-inc-009b", ["h-inc-009b"], ["T1110"])],
                "findings": [],
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 2},
    },
    {
        "id": "INC-010_DUPLICATE_PREVENTION",
        "description": "Same evidence processed twice does not duplicate the incident (7.5)",
        "steps": [
            {
                "groups": [_group("g-inc-010a", ["h-inc-010"], ["T1021.001"])],
                "findings": [_finding("CF-inc-010", ["h-inc-010"])],
                "repeat": True,
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 1},
    },
    {
        "id": "INC-011_CLOSED_REOPEN",
        "description": "New activity against a closed incident does not reopen it (7.6)",
        "steps": [
            {
                "groups": [_group("g-inc-011a", ["h-inc-011"], ["T1021.001"])],
                "findings": [],
                "close_after": True,
                "policy_id": "I003",
            },
            {
                "groups": [_group("g-inc-011b", ["h-inc-011"], ["T1110"])],
                "findings": [],
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 2},
    },
    {
        "id": "INC-012_SUPPRESSION",
        "description": "Suppression blocks repeat fingerprint for the duration (7.21)",
        "steps": [
            {
                "groups": [_group("g-inc-012a", ["h-inc-012"], ["T1021.001"])],
                "findings": [],
                "suppress_after": True,
                "policy_id": "I003",
            },
            {
                "groups": [_group("g-inc-012a", ["h-inc-012"], ["T1021.001"])],
                "findings": [],
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 1, "status": "SUPPRESSED"},
    },
    {
        "id": "INC-013_ANALYST_ESCALATION",
        "description": "Analyst escalation policy I008 always eligible (7.3)",
        "steps": [
            {
                "groups": [
                    _group("g-inc-013a", ["h-inc-013"], ["T1078"], severity="medium")
                ],
                "findings": [],
                "policy_id": "I008",
            },
        ],
        "expected": {
            "incident_created": True,
            "policy_id": "I008",
            "severity": "medium",
        },
    },
    {
        "id": "INC-014_MULTI_HOST_SUPPORTED",
        "description": "Multi-host with correlation is eligible (7.27)",
        "steps": [
            {
                "groups": [
                    _group("g-inc-014a", ["h-inc-014a", "h-inc-014b"], ["T1021.001"])
                ],
                "findings": [_finding("CF-inc-014", ["h-inc-014a", "h-inc-014b"])],
                "policy_id": "I001",
            },
        ],
        "expected": {"incident_created": True, "policy_id": "I001", "entity_count": 2},
    },
    {
        "id": "INC-015_HIGH_RISK_WITHOUT_ACTIVITY",
        "description": "High risk without groups/findings does not auto-create (7.28)",
        "steps": [
            {
                "groups": [],
                "findings": [],
                "risks": [
                    _risk(
                        "ER-inc-015", 90.0, severity="critical", entity_id="h-inc-015"
                    )
                ],
            },
        ],
        "expected": {"incident_created": False},
    },
    {
        "id": "INC-016_EVIDENCE_PRESERVED",
        "description": "Evidence is preserved in the incident (7.12)",
        "steps": [
            {
                "groups": [_group("g-inc-016a", ["h-inc-016"], ["T1021.001"])],
                "findings": [_finding("CF-inc-016", ["h-inc-016"])],
                "policy_id": "I003",
            },
        ],
        "expected": {"incident_created": True, "evidence_count": 2},
    },
    {
        "id": "INC-017_DETERMINISTIC_FINGERPRINT",
        "description": "Same inputs always produce the same fingerprint (7.4)",
        "steps": [
            {
                "groups": [_group("g-inc-017a", ["h-inc-017"], ["T1021.001"])],
                "findings": [_finding("CF-inc-017", ["h-inc-017"])],
                "repeat": True,
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 1, "fingerprint_stable": True},
    },
    {
        "id": "INC-018_IDEMPOTENCY",
        "description": "Running the same engine three times produces identical state (7.47)",
        "steps": [
            {
                "groups": [_group("g-inc-018a", ["h-inc-018"], ["T1021.001"])],
                "findings": [_finding("CF-inc-018", ["h-inc-018"])],
                "repeat": 3,
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 1},
    },
    {
        "id": "INC-019_CONCURRENCY",
        "description": "Concurrent creation of the same incident produces 1 incident (7.46)",
        "steps": [
            {
                "groups": [_group("g-inc-019a", ["h-inc-019"], ["T1021.001"])],
                "findings": [_finding("CF-inc-019", ["h-inc-019"])],
                "concurrent": True,
                "policy_id": "I003",
            },
        ],
        "expected": {"incidents_created": 1},
    },
    {
        "id": "INC-020_SLA",
        "description": "Priority derives from severity and risk (7.9)",
        "steps": [
            {
                "groups": [_group("g-inc-020a", ["h-inc-020"], ["T1486"])],
                "findings": [],
                "risks": [
                    _risk(
                        "ER-inc-020", 85.0, severity="critical", entity_id="h-inc-020"
                    )
                ],
                "policy_id": "I006",
            },
        ],
        "expected": {"incident_created": True, "priority": "P1"},
    },
]
