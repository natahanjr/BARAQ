"""Phase 6 regression corpus (spec 6.59, 6.87): RISK-001..RISK-025.

Every known-problem scenario is pinned here through the REAL risk engine:
typed evidence -> factors -> deterministic score/severity/state/trend.
RISK-020..RISK-025 pin the isolation boundary (v1 counters untouched).
"""
from __future__ import annotations

from datetime import timedelta

import pytest

import backend.config as config
from backend.risk import engine
from backend.risk.models import EntityRiskV2Factor

from tests.risk.helpers import (
    RISK_T0,
    alert_evidence,
    finding_evidence,
    group_evidence,
    stored_audit,
    stored_factors,
    stored_risks,
)

EV = RISK_T0


def test_risk_001_single_alert_overload(db):
    engine.apply_alert(
        db, alert_evidence("ALR-000001", "h1", severity="medium"), now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 11.0  # tier (medium=3) + recency 8
    assert risk.severity == "MINIMAL"
    assert risk.state == "NORMAL"
    assert risk.alert_count == 1


def test_risk_002_group_explosion(db):
    engine.apply_group(
        db, group_evidence("g-a", "h1", ["T1021.001"], alert_count=10), now=EV,
    )
    engine.apply_group(
        db, group_evidence("g-b", "h2", ["T1021.001"], alert_count=50), now=EV,
    )
    assert engine.risk_for_entity(db, "HOST", "h1").score == 42.0
    assert engine.risk_for_entity(db, "HOST", "h2").score == 42.0
    assert engine.risk_for_entity(db, "HOST", "h2").alert_count == 50


def test_risk_003_correlation_double_count(db):
    engine.apply_group(db, group_evidence("g-c", "h1", ["T1110"]), now=EV)
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 48.0
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert len(factor_ids) == 5


def test_risk_004_recency(db):
    engine.apply_group(
        db,
        group_evidence("g-d", "h1", ["T1021.001"]),
        now=EV,
    )
    engine.apply_group(
        db,
        group_evidence("g-e", "h2", ["T1021.001"], observed=EV - timedelta(hours=2)),
        now=EV,
    )
    assert engine.risk_for_entity(db, "HOST", "h1").score == 42.0
    assert engine.risk_for_entity(db, "HOST", "h2").score == pytest.approx(round(34.0 * 0.5 ** (2 / 24), 4), abs=0.001)


def test_risk_005_decay(db):
    engine.apply_group(
        db,
        group_evidence("g-f", "h1", ["T1021.001"], observed=EV - timedelta(hours=24)),
        now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == pytest.approx(17.0)
    assert risk.severity == "MINIMAL"


def test_risk_006_expiration(db):
    engine.apply_group(
        db,
        group_evidence("g-g", "h1", ["T1021.001"], observed=EV - timedelta(hours=200)),
        now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 0.0
    assert risk.severity == "MINIMAL"
    assert engine.expire_factors(db, now=EV) >= 3


def test_risk_007_repetition(db):
    for index in range(5):
        engine.apply_alert(
            db, alert_evidence(f"ALR-{index:06d}", "h1", detector="D100", severity="high"),
            now=EV,
        )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 43.0
    repetition = [
        f for f in stored_factors(db)
        if f.risk_id == risk.risk_id and f.factor_id == "RF007_REPETITION"
    ]
    assert len(repetition) == 4


def test_risk_008_propagation_bounded(db):
    engine.apply_group(db, group_evidence("g-h", "h1", ["T1021.001"]), now=EV)
    engine.apply_propagation(
        db, "USER", "u1", from_entity="HOST:h1",
        relationship_type="host_to_user", now=EV,
    )
    user_risk = engine.risk_for_entity(db, "USER", "u1")
    assert user_risk.score == 16.0  # bounded weight 8 + fresh recency 8
    assert user_risk.confidence == 0.5


def test_risk_009_severity_cap(db):
    for index, technique in enumerate(("T1110", "T1021.001", "T1059.001", "T1047")):
        engine.apply_group(
            db, group_evidence(f"g{index}", "h1", [technique]), now=EV,
        )
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 100.0
    assert risk.severity == "CRITICAL"
    assert risk.state == "CRITICAL"


def test_risk_010_determinism(db):
    evidence = [
        group_evidence("g-i1", "h-a", ["T1021.001"]),
        group_evidence("g-i2", "h-a", ["T1110"]),
    ]
    engine.ingest_evidence(db, evidence, now=EV)
    engine.ingest_evidence(db, list(reversed(evidence))[:1], now=EV)
    a = engine.risk_for_entity(db, "HOST", "h-a")
    engine.apply_group(db, group_evidence("g-i3", "h-b", ["T1110"]), now=EV)
    engine.apply_group(db, group_evidence("g-i4", "h-b", ["T1021.001"]), now=EV)
    b = engine.risk_for_entity(db, "HOST", "h-b")
    assert a.score == b.score == 66.0


def test_risk_011_idempotency(db):
    evidence = [group_evidence("g-j", "h1", ["T1021.001"])]
    engine.ingest_evidence(db, evidence, now=EV)
    factor_count = len(stored_factors(db))
    engine.ingest_evidence(db, evidence, now=EV)
    assert len(stored_factors(db)) == factor_count
    assert engine.risk_for_entity(db, "HOST", "h1").score == 42.0


def test_risk_012_peak(db):
    engine.apply_group(db, group_evidence("g-k", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.peak_score == 42.0
    engine.recalculate_entity(db, risk.risk_id, now=EV + timedelta(hours=24))
    db.refresh(risk)
    assert risk.score == pytest.approx(17.0)
    assert risk.peak_score == 42.0
    assert risk.trend == "FALLING"


def test_risk_013_threshold_crossed(db):
    engine.apply_alert(
        db, alert_evidence("ALR-000001", "h1", severity="medium"), now=EV,
    )
    engine.apply_group(db, group_evidence("g-l", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 45.0
    assert risk.severity == "MEDIUM"
    assert risk.state == "HIGH"
    events = [
        a for a in stored_audit(db)
        if a.risk_id == risk.risk_id and a.action == "RISK_THRESHOLD_CROSSED"
    ]
    assert events[0].details["severities"] == ["LOW", "MEDIUM"]


def test_risk_014_stale(db):
    engine.apply_group(db, group_evidence("g-m", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    engine.recalculate_entity(db, risk.risk_id, now=EV + timedelta(hours=2))
    db.refresh(risk)
    assert risk.state == "STALE"


def test_risk_015_trend(db):
    engine.apply_alert(
        db, alert_evidence("ALR-000001", "h-a", severity="medium"), now=EV,
    )
    engine.apply_group(db, group_evidence("g-n1", "h-a", ["T1021.001"]), now=EV)
    engine.apply_group(db, group_evidence("g-n2", "h-b", ["T1021.001"]), now=EV)
    assert engine.risk_for_entity(db, "HOST", "h-a").trend == "RISING"
    assert engine.risk_for_entity(db, "HOST", "h-b").trend == "UNKNOWN"
    engine.recalculate_entity(
        db, engine.risk_for_entity(db, "HOST", "h-b").risk_id,
        now=EV + timedelta(hours=24),
    )
    assert engine.risk_for_entity(db, "HOST", "h-b").trend == "FALLING"


def test_risk_016_explanation(db):
    engine.apply_group(db, group_evidence("g-o", "h1", ["T1021.001"]), now=EV)
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    total = 0.0
    for factor in stored_factors(db):
        if factor.risk_id != risk.risk_id:
            continue
        assert factor.reason
        assert factor.evidence
        total += factor.contribution
    assert total == risk.score == 52.0


def test_risk_017_no_magic(db):
    engine.apply_group(
        db,
        {
            "kind": "BEHAVIOR_GROUP",
            "group_id": "g-p", "hosts": ["h1"], "users": ["u1"],
            "source_ips": ["203.0.113.5"], "destination_ips": [],
            "techniques": ["T9999"], "severity": "high", "alert_count": 10,
            "first_seen": EV, "last_seen": EV,
        },
        now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 24.0
    with pytest.raises(ValueError):
        engine.apply_propagation(
            db, "HOST", "h1", from_entity="HOST:x",
            relationship_type="suspicious", now=EV,
        )


def test_risk_018_direct_vs_contextual(db):
    engine.apply_group(db, group_evidence("g-q", "h1", ["T1021.001"]), now=EV)
    engine.apply_propagation(
        db, "HOST", "h1", from_entity="USER:u1",
        relationship_type="user_to_host", now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 50.0
    assert risk.confidence == pytest.approx(0.84)


def test_risk_019_model_version(db):
    engine.apply_group(db, group_evidence("g-r", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.risk_model_version == "1.0.0"
    from backend.risk.models import EntityRiskV2Snapshot

    from sqlalchemy import select

    snapshots = db.scalars(
        select(EntityRiskV2Snapshot).where(
            EntityRiskV2Snapshot.risk_id == risk.risk_id
        )
    ).all()
    assert all(s.risk_model_version == "1.0.0" for s in snapshots)


def test_risk_020_isolation(db):
    from sqlalchemy import text

    def counts():
        return {
            t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
            for t in (
                "alerts", "incidents", "v2_events", "v2_alerts",
                "behavior_groups", "behavior_group_members",
                "correlation_findings", "correlation_members",
                "entity_risk", "entity_risk_events", "playbook_runs",
            )
        }

    before = counts()
    engine.apply_group(db, group_evidence("g-s", "h1", ["T1021.001"]), now=EV)
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=EV)
    db.commit()
    assert counts() == before


def test_risk_021_metrics(db):
    from backend.risk.metrics import risk_metrics

    engine.apply_group(db, group_evidence("g-t1", "h1", ["T1021.001"]), now=EV)
    engine.apply_finding(db, finding_evidence("CF-000001", ["h1"]), now=EV)
    metrics = risk_metrics(db)
    assert metrics["total_entities"] == 3
    assert metrics["entities_with_risk"] == 3
    assert metrics["medium"] == 1
    assert metrics["max_score"] == 52.0
    assert metrics["calculation_latency"]["p50_ms"] >= 0


def test_risk_022_api_shape(db):
    engine.apply_group(db, group_evidence("g-u", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    payload = risk.to_dict()
    for field in (
        "risk_id", "entity_type", "entity_id", "entity_name", "score",
        "severity", "state", "confidence", "trend", "peak_score", "peak_at",
        "first_seen", "last_seen", "last_calculated_at",
        "active_factor_count", "evidence_count", "alert_count",
        "group_count", "correlation_count", "risk_model_version",
        "created_at", "updated_at",
    ):
        assert field in payload


def test_risk_023_entity_types(db):
    engine.apply_alert(
        db,
        alert_evidence(
            "ALR-000001", "h1", user="u1", source="203.0.113.1",
            destination_ip="10.0.0.1", account="svc-1", process="pwsh.exe",
        ),
        now=EV,
    )
    types = {r.entity_type for r in stored_risks(db)}
    assert types == {
        "HOST", "USER", "SOURCE_IP", "DESTINATION_IP", "ACCOUNT", "PROCESS",
    }


def test_risk_024_attribution(db):
    engine.apply_group(db, group_evidence("g-v", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    actions = [
        a for a in stored_audit(db) if a.risk_id == risk.risk_id
    ]
    names = {a.action for a in actions}
    assert {"RISK_CREATED", "FACTOR_ADDED", "RISK_RECALCULATED"} <= names
    assert all(a.actor == "system" for a in actions)
    assert all(a.model_version == "1.0.0" for a in actions)


def test_risk_025_explanation_mismatch(db):
    engine.apply_group(db, group_evidence("g-w", "h1", ["T1021.001"]), now=EV)
    risk = engine.risk_for_entity(db, "HOST", "h1")
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert factor_ids == {
        "RF003_LATERAL_MOVEMENT", "RF010_BEHAVIOR_GROUP",
        "RF009_ALERT_SEVERITY", "RF008_RECENCY",
    }
    total = sum(
        f.contribution for f in stored_factors(db) if f.risk_id == risk.risk_id
    )
    assert total == risk.score == 42.0


def test_dod_acceptance_72_high_rising(db):
    """DoD (spec 6.88): 30 alerts -> 5 groups -> 1 correlation -> 72 HIGH RISING."""
    from backend.correlation.engine import correlate

    from tests.correlation.helpers import canonical_specs, make_groups

    groups = make_groups(db, canonical_specs(), now=EV)
    assert len(groups) == 5
    assert sum(g.alert_count for g in groups) == 30
    findings = correlate(db, now=EV)
    assert len(findings) == 1
    engine.apply_groups(
        db,
        [
            {
                "group_id": g.behavior_group_id,
                "hosts": list(g.host_ids or []),
                "users": list(g.user_ids or []),
                "source_ips": list(g.source_ips or []),
                "destination_ips": list((g.observables or {}).get("destination_ips", [])),
                "techniques": list(g.mitre_techniques or []),
                "severity": g.highest_severity or "low",
                "alert_count": g.alert_count,
                "first_seen": g.first_seen,
                "last_seen": g.last_seen,
            }
            for g in groups
        ],
        now=EV,
    )
    engine.apply_finding(
        db,
        {
            "kind": "CORRELATION_FINDING",
            "correlation_id": findings[0].correlation_id,
            "correlation_type": findings[0].correlation_type,
            "hosts": list(findings[0].hosts or []),
            "users": list(findings[0].users or []),
            "source_ips": list(findings[0].source_ips or []),
            "member_group_ids": list(findings[0].member_group_ids or []),
            "confidence": findings[0].confidence,
            "first_seen": findings[0].first_seen,
            "last_seen": findings[0].last_seen,
        },
        now=EV,
    )
    risk = engine.risk_for_entity(db, "HOST", "10.0.0.7")
    assert risk.score == pytest.approx(72.0, abs=0.01)
    assert risk.severity == "HIGH"
    assert risk.state == "HIGH"
    assert risk.trend == "RISING"