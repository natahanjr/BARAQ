"""Phase 6 acceptance / DoD test (spec 6.88).

30 Alerts -> 5 Behavior Groups -> 1 Correlation Finding
   -> Host risk score 72, severity HIGH, state HIGH, trend RISING,
      fully traceable "why is this entity high risk?".

Composition for host 10.0.0.7 (weights from config):
    RF001_EXTERNAL_ACCESS           +12   (G4 external logon targets it)
    RF003_LATERAL_MOVEMENT           +18   (G5 lateral movement)
    RF005_EXECUTION                   +8   (G5 PowerShell / WMI execution)
    RF010_BEHAVIOR_GROUP             +10   (G5 membership)
    RF009_ALERT_SEVERITY (high tier)  +6   (G5 high severity group)
    RF006_MULTI_STAGE_CORRELATION    +10   (CF-000001 membership)
    RF008_RECENCY                     +8   (recent activity)
    TOTAL                             72   HIGH RISING
"""
from __future__ import annotations

import pytest

from backend.correlation.engine import correlate
from backend.correlation.models import CorrelationFindingRecord
from backend.risk import engine as risk_engine

from tests.correlation.helpers import CORR_T0, canonical_specs, make_groups
from tests.risk.helpers import stored_risks


def _group_evidence(group) -> dict:
    return {
        "kind": "BEHAVIOR_GROUP",
        "group_id": group.behavior_group_id,
        "hosts": list(group.host_ids or []),
        "users": list(group.user_ids or []),
        "source_ips": list(group.source_ips or []),
        "destination_ips": list((group.observables or {}).get("destination_ips", [])),
        "techniques": list(group.mitre_techniques or []),
        "tactics": list(group.mitre_tactics or []),
        "severity": group.highest_severity or "low",
        "alert_count": group.alert_count,
        "alert_ids": list(group.alert_ids or []),
        "first_seen": group.first_seen,
        "last_seen": group.last_seen,
    }


def test_dod_30_alerts_5_groups_1_finding_host_risk_72(db):
    groups = make_groups(db, canonical_specs(), now=CORR_T0)
    assert len(groups) == 5
    assert sum(g.alert_count for g in groups) == 30

    findings = correlate(db, now=CORR_T0)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.member_group_ids and len(finding.member_group_ids) == 5
    assert "10.0.0.7" in (finding.hosts or [])

    risk_engine.apply_groups(
        db, [_group_evidence(g) for g in groups], now=CORR_T0
    )
    risk_engine.apply_finding(
        db,
        {
            "kind": "CORRELATION_FINDING",
            "correlation_id": finding.correlation_id,
            "correlation_type": finding.correlation_type,
            "hosts": list(finding.hosts or []),
            "users": list(finding.users or []),
            "source_ips": list(finding.source_ips or []),
            "member_group_ids": list(finding.member_group_ids or []),
            "confidence": finding.confidence,
            "first_seen": finding.first_seen,
            "last_seen": finding.last_seen,
        },
        now=CORR_T0,
    )
    db.commit()

    # 30 alerts reached risk through the groups (never individually).
    hosts = [r for r in stored_risks(db) if r.entity_type == "HOST"]
    assert sum(r.alert_count for r in hosts) == 30

    risk = risk_engine.risk_for_entity(db, "HOST", "10.0.0.7")
    assert risk is not None
    assert risk.risk_id.startswith("ER-")
    assert risk.score == pytest.approx(72.0, abs=0.01)
    assert risk.severity == "HIGH"
    assert risk.state == "HIGH"
    assert risk.trend == "RISING"
    assert risk.peak_score == pytest.approx(72.0, abs=0.01)
    assert risk.alert_count == 10
    assert risk.group_count == 1
    assert risk.correlation_count == 1
    assert risk.risk_model_version == "1.0.0"
    assert risk.confidence == 1.0

    # Why is this entity high risk? Every contribution traces to evidence.
    from backend.risk.calculator import calculate_risk
    from backend.risk.models import EntityRiskV2Factor
    from sqlalchemy import select

    factors = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk.risk_id)
        .order_by(EntityRiskV2Factor.id)
    ).all()
    by_factor: dict[str, float] = {}
    for factor in factors:
        assert factor.reason
        assert factor.evidence
        by_factor[factor.factor_id] = by_factor.get(factor.factor_id, 0.0) + factor.contribution

    assert by_factor == {
        "RF001_EXTERNAL_ACCESS": 12.0,
        "RF003_LATERAL_MOVEMENT": 18.0,
        "RF005_EXECUTION": 8.0,
        "RF010_BEHAVIOR_GROUP": 10.0,
        "RF009_ALERT_SEVERITY": 6.0,
        "RF006_MULTI_STAGE_CORRELATION": 10.0,
        "RF008_RECENCY": 8.0,
    }
    assert sum(by_factor.values()) == 72.0

    calculation = calculate_risk(
        [
            {
                "factor_id": f.factor_id, "factor_type": f.factor_type,
                "source_type": f.source_type, "source_id": f.source_id,
                "value": f.value, "weight": f.weight, "origin": f.origin,
                "created_at": f.created_at, "expires_at": f.expires_at,
                "reason": f.reason, "evidence": f.evidence,
            }
            for f in factors
        ],
        CORR_T0,
    )
    assert calculation.final_score == pytest.approx(72.0, abs=0.01)
    assert calculation.severity == "HIGH"
    assert len(calculation.factor_contributions) == 7