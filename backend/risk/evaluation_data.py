"""Phase 6 labeled evaluation corpus (spec 6.57-6.58).

Small, deterministic, hand-labeled dataset measuring the risk layer. Each
scenario feeds typed evidence through the real engine with a fixed clock,
then expects exact scores/severities/states/trends and exact factor sets -
no fabricated accuracy percentages anywhere (6.56).

Weights (config): RF001 12, RF002 14, RF003 18, RF004 10, RF005 8, RF006 10,
RF007 curve (15/8/4/2), RF008 8, RF009 tier (crit 8/high 6/med 3/low 1),
RF010 10, RF011 10, RF012 8, RF013 8. Decay: 0.5^(age_hours/24).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

T0 = datetime(2026, 8, 18, 10, 0, 0, tzinfo=UTC)

#: decay(2h) = 0.5^(2/24) - exact value used by RISK-004.
DECAY_2H = round(0.5 ** (2.0 / 24.0), 4)


def _group(
    group_id: str,
    host: str,
    techniques: list[str],
    severity: str = "high",
    alert_count: int = 10,
    observed: datetime = T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
    destination: str | None = None,
    external: bool = False,
) -> dict:
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group_id,
        "hosts": [host],
        "users": [user],
        "source_ips": [source],
        "destination_ips": [destination] if destination else [],
        "techniques": techniques,
        "severity": severity,
        "alert_count": alert_count,
        "first_seen": observed,
        "last_seen": observed,
        "external_source": external,
    }


def _alert(
    alert_id: str,
    host: str,
    detector: str = "D100",
    severity: str = "medium",
    observed: datetime = T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
    technique: str = "T1110",
) -> dict:
    return {
        "kind": "ALERT",
        "alert_id": alert_id,
        "detector_id": detector,
        "host": host,
        "user": user,
        "source_ip": source,
        "severity": severity,
        "mitre_technique": technique,
        "first_seen": observed,
        "last_seen": observed,
    }


def _finding(
    finding_id: str,
    hosts: list[str],
    observed: datetime = T0,
    user: str = "u-eval",
    source: str = "203.0.113.5",
) -> dict:
    return {
        "kind": "CORRELATION_FINDING",
        "correlation_id": finding_id,
        "correlation_type": "MULTI_STAGE",
        "hosts": hosts,
        "users": [user],
        "source_ips": [source],
        "member_group_ids": ["g-eval"],
        "confidence": 0.88,
        "first_seen": observed,
        "last_seen": observed,
    }


SCENARIOS: list[dict] = [
    {
        "id": "RISK-001_SINGLE_ALERT_OVERLOAD",
        "description": "One medium alert must never overload an entity (6.12)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert("ALR-001001", "h001", severity="medium"),
                ],
            },
        ],
        "expected": {
            "HOST:h001": {
                "score": 11.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "factors": ["RF009_ALERT_SEVERITY", "RF008_RECENCY"],
            },
        },
    },
    {
        "id": "RISK-002_GROUP_EXPLOSION",
        "description": "50 alerts in one group weigh the same as 10 (6.12)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-a", "h002", ["T1021.001"], alert_count=10),
                    _group("g-b", "h002b", ["T1021.001"], alert_count=50),
                ],
            },
        ],
        "expected": {
            "HOST:h002": {
                "score": 42.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "alert_count": 10,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
            "HOST:h002b": {
                "score": 42.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "alert_count": 50,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
        },
    },
    {
        "id": "RISK-003_CORRELATION_DOUBLE_COUNT",
        "description": "Finding membership adds one sequence factor, never the member factors again (6.16)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-c", "h003", ["T1110"]),
                    _finding("CF-000100", ["h003"]),
                ],
            },
        ],
        "expected": {
            "HOST:h003": {
                "score": 48.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "alert_count": 10,
                "group_count": 1,
                "correlation_count": 1,
                "factors": [
                    "RF002_CREDENTIAL_ACCESS",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                    "RF006_MULTI_STAGE_CORRELATION",
                ],
            },
        },
    },
    {
        "id": "RISK-004_RECENCY",
        "description": "Recent evidence keeps risk current; old evidence loses the recency bonus (6.11)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-d", "h004a", ["T1021.001"]),
                    _group(
                        "g-e", "h004b", ["T1021.001"], observed=T0 - timedelta(hours=2)
                    ),
                ],
            },
        ],
        "expected": {
            "HOST:h004a": {"score": 42.0},
            "HOST:h004b": {
                "score": 32.0916,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                ],
            },
        },
    },
    {
        "id": "RISK-005_DECAY",
        "description": "Deterministic half-life decay: 24h old evidence keeps half its contribution (6.19)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group(
                        "g-f", "h005", ["T1021.001"], observed=T0 - timedelta(hours=24)
                    ),
                ],
            },
        ],
        "expected": {
            "HOST:h005": {
                "score": 17.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                ],
            },
        },
    },
    {
        "id": "RISK-006_EXPIRATION",
        "description": "Factors expire after their lifetime; history remains (6.21, 6.72)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group(
                        "g-g", "h006", ["T1021.001"], observed=T0 - timedelta(hours=200)
                    ),
                ],
            },
            {"at": T0, "expire": True},
        ],
        "expected": {
            "HOST:h006": {
                "score": 0.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                ],
            },
        },
    },
    {
        "id": "RISK-007_REPETITION",
        "description": "Repeated identical alerts add diminishing amounts 15/8/4/2 (6.13)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert(f"ALR-00100{i}", "h007", detector="D100", severity="high")
                    for i in range(5)
                ],
            },
        ],
        "expected": {
            "HOST:h007": {
                "score": 43.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "factors": [
                    "RF009_ALERT_SEVERITY",
                    "RF007_REPETITION",
                    "RF008_RECENCY",
                ],
                "repetition_count": 4,
            },
        },
    },
    {
        "id": "RISK-008_PROPAGATION_BOUNDED",
        "description": "Contextual propagation is bounded, weighted, evidenced, expiring - never risk copying (6.27)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-h", "h008a", ["T1021.001"]),
                ],
            },
            {
                "at": T0,
                "propagate": {
                    "target_entity_type": "USER",
                    "target_entity_id": "u008a",
                    "from_entity": "HOST:h008a",
                    "relationship_type": "host_to_user",
                    "reason": "user accounts on a high-risk host",
                },
            },
        ],
        "expected": {
            "USER:u008a": {
                "score": 16.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "confidence": 0.5,
                "factors": ["RF006_MULTI_STAGE_CORRELATION", "RF008_RECENCY"],
            },
        },
    },
    {
        "id": "RISK-009_SEVERITY_CAP",
        "description": "Scores are hard-capped at 100 (6.34)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g1", "h009", ["T1110"]),
                    _group("g2", "h009", ["T1021.001"]),
                    _group("g3", "h009", ["T1059.001"]),
                    _group("g4", "h009", ["T1047"]),
                    _finding("CF-000101", ["h009"]),
                ],
            },
        ],
        "expected": {
            "HOST:h009": {"score": 100.0, "severity": "CRITICAL", "state": "CRITICAL"},
        },
    },
    {
        "id": "RISK-010_DETERMINISM",
        "description": "Identical evidence in any order produces identical scores (6.31)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-i1", "h010a", ["T1021.001"]),
                    _group("g-i2", "h010a", ["T1110"]),
                ],
            },
            {
                "at": T0,
                "evidence": [
                    _group("g-i3", "h010b", ["T1110"]),
                    _group("g-i4", "h010b", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h010a": {
                "score": 66.0,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF002_CREDENTIAL_ACCESS",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
            "HOST:h010b": {
                "score": 66.0,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF002_CREDENTIAL_ACCESS",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
        },
    },
    {
        "id": "RISK-011_IDEMPOTENCY",
        "description": "Re-ingesting the same evidence adds nothing (6.35)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-j", "h011", ["T1021.001"]),
                ],
            },
            {"at": T0, "replay": True},
        ],
        "expected": {
            "HOST:h011": {"score": 42.0, "factor_count": 4},
        },
    },
    {
        "id": "RISK-012_PEAK",
        "description": "Peak score is the historical maximum; it never decreases (6.22)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-k", "h012", ["T1021.001"]),
                ],
            },
            {"at": T0 + timedelta(hours=24), "recalculate_entities": ["HOST:h012"]},
        ],
        "expected": {
            "HOST:h012": {
                "score": 17.0,
                "severity": "MINIMAL",
                "state": "STALE",
                "peak_score": 42.0,
                "trend": "FALLING",
            },
        },
    },
    {
        "id": "RISK-013_THRESHOLD_CROSSED",
        "description": "Severity threshold crossings are audited with the crossed severities (6.44)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert("ALR-001300", "h013", severity="medium"),
                ],
            },
            {
                "at": T0,
                "evidence": [
                    _group("g-l", "h013", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h013": {
                "score": 45.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "crossed": ["LOW", "MEDIUM"],
            },
        },
    },
    {
        "id": "RISK-014_STALE",
        "description": "Entities without fresh calculations become STALE (6.76)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-m", "h014", ["T1021.001"]),
                ],
            },
            {"at": T0 + timedelta(hours=2), "recalculate_entities": ["HOST:h014"]},
        ],
        "expected": {
            "HOST:h014": {"state": "STALE"},
        },
    },
    {
        "id": "RISK-015_TREND",
        "description": "Trend is descriptive RISING/STABLE/FALLING from snapshots (6.24)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert("ALR-001501", "h015a", severity="medium"),
                ],
            },
            {
                "at": T0,
                "evidence": [
                    _group("g-n1", "h015a", ["T1021.001"]),
                    _group("g-n2", "h015b", ["T1021.001"]),
                ],
            },
            {"at": T0 + timedelta(hours=24), "recalculate_entities": ["HOST:h015b"]},
        ],
        "expected": {
            "HOST:h015a": {"trend": "RISING", "score": 45.0},
            "HOST:h015b": {"trend": "FALLING", "score": 17.0},
        },
    },
    {
        "id": "RISK-016_EXPLANATION",
        "description": "Every contribution carries provenance and sums to the final score (6.32, 6.42)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-o", "h016", ["T1021.001"]),
                    _finding("CF-000102", ["h016"]),
                ],
            },
        ],
        "expected": {
            "HOST:h016": {
                "score": 52.0,
                "severity": "MEDIUM",
                "state": "HIGH",
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                    "RF006_MULTI_STAGE_CORRELATION",
                ],
            },
        },
    },
    {
        "id": "RISK-017_NO_MAGIC",
        "description": "Unknown techniques are ignored and unregistered relationships are rejected (6.43)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    {
                        "kind": "BEHAVIOR_GROUP",
                        "group_id": "g-p",
                        "hosts": ["h017"],
                        "users": ["u017"],
                        "source_ips": ["203.0.113.5"],
                        "destination_ips": [],
                        "techniques": ["T9999"],
                        "severity": "high",
                        "alert_count": 10,
                        "first_seen": T0,
                        "last_seen": T0,
                    },
                ],
            },
            {
                "at": T0,
                "propagate": {
                    "target_entity_type": "HOST",
                    "target_entity_id": "h017",
                    "from_entity": "HOST:x",
                    "relationship_type": "suspicious",
                    "reason": "suspicious link",
                    "expect_error": True,
                },
            },
        ],
        "expected": {
            "HOST:h017": {
                "score": 24.0,
                "factors": [
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
        },
    },
    {
        "id": "RISK-018_DIRECT_VS_CONTEXTUAL",
        "description": "Confidence is the direct-evidence share of the score (6.81)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-q", "h018", ["T1021.001"]),
                ],
            },
            {
                "at": T0,
                "propagate": {
                    "target_entity_type": "HOST",
                    "target_entity_id": "h018",
                    "from_entity": "USER:u018",
                    "relationship_type": "user_to_host",
                    "reason": "host used by a user present elsewhere",
                },
            },
        ],
        "expected": {
            "HOST:h018": {
                "score": 50.0,
                "confidence": 0.84,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                    "RF006_MULTI_STAGE_CORRELATION",
                ],
            },
        },
    },
    {
        "id": "RISK-019_MODEL_VERSION",
        "description": "Every record and snapshot carries the risk model version (6.39, 6.66)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-r", "h019", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h019": {
                "score": 42.0,
                "model_version": "1.0.0",
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
        },
    },
    {
        "id": "RISK-020_ISOLATION",
        "description": "The risk engine never touches alerts, groups, findings or incidents (6.61)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-s", "h020", ["T1021.001"]),
                    _finding("CF-000103", ["h020"]),
                ],
            },
        ],
        "expected": {
            "HOST:h020": {"score": 52.0},
            "isolation": [
                "v2_alerts",
                "behavior_groups",
                "correlation_findings",
                "incidents",
            ],
        },
    },
    {
        "id": "RISK-021_METRICS",
        "description": "Metrics aggregate the store without fabrication (6.55)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group(
                        "g-t1",
                        "h021",
                        ["T1021.001"],
                        user="u021",
                        source="203.0.113.21",
                    ),
                    _group(
                        "g-t2", "h021b", ["T1110"], user="u021", source="203.0.113.21"
                    ),
                    _finding("CF-000104", ["h021"], user="u021", source="203.0.113.21"),
                ],
            },
        ],
        "expected": {
            "HOST:h021": {"score": 52.0},
            "metrics_delta": {"total_entities": 4, "entities_with_risk": 4},
        },
    },
    {
        "id": "RISK-022_API_SHAPE",
        "description": "The record exposes every contract field (6.4)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-u", "h022", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h022": {"score": 42.0},
        },
    },
    {
        "id": "RISK-023_ENTITY_TYPES",
        "description": "All six entity types are supported (6.2)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    {
                        "kind": "ALERT",
                        "alert_id": "ALR-002300",
                        "detector_id": "D100",
                        "host": "h023",
                        "user": "u023",
                        "source_ip": "203.0.113.23",
                        "destination_ip": "10.0.0.23",
                        "account": "svc-023",
                        "process": "powershell.exe",
                        "severity": "medium",
                        "first_seen": T0,
                        "last_seen": T0,
                    },
                ],
            },
        ],
        "expected": {
            "HOST:h023": {"score": 11.0},
            "USER:u023": {"score": 11.0},
            "SOURCE_IP:203.0.113.23": {"score": 11.0},
            "DESTINATION_IP:10.0.0.23": {"score": 11.0},
            "ACCOUNT:svc-023": {"score": 11.0},
            "PROCESS:powershell.exe": {"score": 11.0},
        },
    },
    {
        "id": "RISK-024_ATTRIBUTION",
        "description": "Every state change is attributed with actor and model version (6.44, 6.70)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-v", "h024", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h024": {
                "score": 42.0,
                "audit_actions": [
                    "RISK_CREATED",
                    "FACTOR_ADDED",
                    "RISK_RECALCULATED",
                ],
            },
        },
    },
    {
        "id": "RISK-025_EXPLANATION_MISMATCH",
        "description": "The explanation lists exactly the stored factors - nothing more, nothing less (6.32)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _group("g-w", "h025", ["T1021.001"]),
                ],
            },
        ],
        "expected": {
            "HOST:h025": {
                "score": 42.0,
                "factors": [
                    "RF003_LATERAL_MOVEMENT",
                    "RF010_BEHAVIOR_GROUP",
                    "RF009_ALERT_SEVERITY",
                    "RF008_RECENCY",
                ],
            },
        },
    },
    {
        "id": "RISK-026_BENIGN_BASELINE",
        "description": "A single benign low-severity event stays minimal and normal (6.7, 6.58)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert("ALR-002601", "h026", severity="low", technique="T9999"),
                ],
            },
        ],
        "expected": {
            "HOST:h026": {
                "score": 9.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "factors": ["RF009_ALERT_SEVERITY", "RF008_RECENCY"],
            },
        },
    },
    {
        "id": "RISK-027_SINGLE_HIGH_EVENT",
        "description": "A single high event stays bounded and explainable - no alert-to-risk explosion (6.12, 6.58)",
        "steps": [
            {
                "at": T0,
                "evidence": [
                    _alert("ALR-002701", "h027", severity="high", technique="T9999"),
                ],
            },
        ],
        "expected": {
            "HOST:h027": {
                "score": 14.0,
                "severity": "MINIMAL",
                "state": "NORMAL",
                "factors": ["RF009_ALERT_SEVERITY", "RF008_RECENCY"],
            },
        },
    },
]
