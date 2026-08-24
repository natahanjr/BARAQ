"""Phase 6 engine tests (spec 6.1, 6.12, 6.13, 6.16, 6.27, 6.30-6.38, 6.42)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

import backend.config as config
from backend.risk import engine
from backend.risk.models import (
    EntityRiskV2,
    EntityRiskV2AuditEvent,
    EntityRiskV2Factor,
    EntityRiskV2Snapshot,
)

from tests.risk.helpers import (
    RISK_T0,
    alert_evidence,
    finding_evidence,
    group_evidence,
    stored_audit,
    stored_factors,
    stored_risks,
    stored_snapshots,
)


def test_get_or_create_claims_once_per_entity(db):
    risk_a = engine.get_or_create_risk(db, "HOST", "h1", now=RISK_T0)
    risk_b = engine.get_or_create_risk(db, "HOST", "h1", now=RISK_T0)
    assert risk_a.risk_id == risk_b.risk_id
    assert risk_a.risk_id.startswith("ER-")
    assert len(stored_risks(db)) == 1
    actions = [a.action for a in stored_audit(db)]
    assert actions.count("RISK_CREATED") == 1


def test_get_or_create_validates(db):
    with pytest.raises(ValueError):
        engine.get_or_create_risk(db, "GADGET", "x", now=RISK_T0)
    with pytest.raises(ValueError):
        engine.get_or_create_risk(db, "HOST", "", now=RISK_T0)


def test_next_risk_id_sequences(db):
    first = engine.get_or_create_risk(db, "HOST", "h1", now=RISK_T0)
    second_id = engine.next_risk_id(db)
    assert second_id.startswith("ER-")
    first_num = int(first.risk_id.split("-")[1])
    second_num = int(second_id.split("-")[1])
    assert second_num > first_num


def test_apply_alert_resolves_all_six_entity_types(db):
    alert = alert_evidence(
        "ALR-000001", "h1", user="u1", source="203.0.113.1",
        destination_ip="10.0.0.1", account="svc-1", process="pwsh.exe",
    )
    engine.apply_alert(db, alert, now=RISK_T0)
    types = {r.entity_type for r in stored_risks(db)}
    assert types == {
        "HOST", "USER", "SOURCE_IP", "DESTINATION_IP", "ACCOUNT", "PROCESS",
    }


def test_apply_alert_severity_tier_dedupes_per_entity(db):
    for index in range(5):
        engine.apply_alert(
            db,
            alert_evidence(f"ALR-{index:06d}", "h1", severity="high"),
            now=RISK_T0,
        )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 43.0
    factors = db.scalars(
        select(EntityRiskV2Factor)
        .where(EntityRiskV2Factor.risk_id == risk.risk_id)
    ).all()
    tier_factors = [f for f in factors if f.factor_id == "RF009_ALERT_SEVERITY"]
    assert len(tier_factors) == 1
    repetition = [f for f in factors if f.factor_id == "RF007_REPETITION"]
    assert len(repetition) == 4
    assert risk.alert_count == 5


def test_apply_group_membership_and_technique_factors(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001", "T1059.001"], alert_count=10),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 50.0
    assert risk.alert_count == 10
    assert risk.group_count == 1
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert factor_ids == {
        "RF003_LATERAL_MOVEMENT", "RF005_EXECUTION", "RF010_BEHAVIOR_GROUP",
        "RF009_ALERT_SEVERITY", "RF008_RECENCY",
    }


def test_apply_group_external_destination_gets_external_access(db):
    engine.apply_group(
        db,
        group_evidence(
            "g4", "h-src", ["T1133"], severity="medium", user="u1",
            source="198.51.100.9", destination="10.0.0.7", alert_count=5,
        ),
        now=RISK_T0,
    )
    target = engine.risk_for_entity(db, "HOST", "10.0.0.7")
    assert target is not None
    assert target.score == 20.0  # RF001 12 + RF008 8
    assert target.group_count == 0  # destination, never a member


def test_apply_group_internal_source_gets_no_external_factor(db):
    engine.apply_group(
        db,
        group_evidence("g5", "h1", ["T1021.001"], source="10.0.0.6"),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert "RF001_EXTERNAL_ACCESS" not in factor_ids


def test_apply_group_unknown_technique_is_ignored(db):
    engine.apply_group(
        db,
        group_evidence("g-x", "h1", ["T9999"], alert_count=10),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 24.0  # RF010 10 + RF009 6 + RF008 8
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert "T9999" not in " ".join(factor_ids)


def test_spread_applies_to_entities_in_many_groups(db):
    engine.apply_groups(
        db,
        [group_evidence(f"g{index}", f"h{index}", ["T1110"]) for index in range(4)],
        now=RISK_T0,
    )
    user_risk = engine.risk_for_entity(db, "USER", "u-eval")
    assert user_risk is not None
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == user_risk.risk_id}
    assert "RF013_ENTITY_SPREAD" in factor_ids
    host_risk = engine.risk_for_entity(db, "HOST", "h0")
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == host_risk.risk_id}
    assert "RF013_ENTITY_SPREAD" not in factor_ids


def test_apply_finding_adds_only_sequence_factor(db):
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1110"]), now=RISK_T0,
    )
    engine.apply_finding(
        db, finding_evidence("CF-000001", ["h1"]), now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 48.0
    assert risk.correlation_count == 1
    factor_ids = {f.factor_id for f in stored_factors(db) if f.risk_id == risk.risk_id}
    assert len(factor_ids) == 5
    assert factor_ids == {
        "RF002_CREDENTIAL_ACCESS", "RF010_BEHAVIOR_GROUP",
        "RF009_ALERT_SEVERITY", "RF008_RECENCY",
        "RF006_MULTI_STAGE_CORRELATION",
    }


def test_apply_propagation_is_bounded_and_expiring(db):
    engine.apply_group(
        db, group_evidence("g1", "h1", ["T1021.001"]), now=RISK_T0,
    )
    engine.apply_propagation(
        db, "USER", "u1",
        from_entity="HOST:h1",
        relationship_type="host_to_user",
        reason="user on high-risk host",
        now=RISK_T0,
    )
    user_risk = engine.risk_for_entity(db, "USER", "u1")
    assert user_risk.score == 16.0  # bounded weight 8 + fresh recency 8
    factor = db.scalars(
        select(EntityRiskV2Factor).where(
            EntityRiskV2Factor.risk_id == user_risk.risk_id,
            EntityRiskV2Factor.source_type == "propagation",
        )
    ).first()
    assert factor.origin == "CONTEXTUAL"
    assert factor.propagation_from == "HOST:h1"
    assert factor.relationship_type == "host_to_user"
    assert factor.expires_at == RISK_T0 + timedelta(
        hours=config.RISK_PROPAGATION_EXPIRES_HOURS
    )


def test_apply_propagation_rejects_unknown_relationship(db):
    with pytest.raises(ValueError):
        engine.apply_propagation(
            db, "HOST", "h1",
            from_entity="HOST:x", relationship_type="suspicious",
            now=RISK_T0,
        )


def test_factors_carry_full_provenance(db):
    engine.apply_group(
        db, group_evidence("g5", "h1", ["T1021.001"], alert_count=10),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    for factor in stored_factors(db):
        if factor.risk_id != risk.risk_id:
            continue
        assert factor.reason
        assert factor.evidence
        assert factor.source_type
        assert factor.source_id
        assert factor.created_at is not None
        # RF008 lives on the recency window rather than a hard expiry (6.11);
        # every other factor carries an expiry.
        if factor.factor_id != "RF008_RECENCY":
            assert factor.expires_at is not None
        assert factor.factor_version == "1.0"


def test_recalculate_creates_snapshot_and_audit(db):
    engine.apply_group(
        db, group_evidence("g5", "h1", ["T1021.001"]), now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    snapshots = [s for s in stored_snapshots(db) if s.risk_id == risk.risk_id]
    assert len(snapshots) == 1
    assert snapshots[0].score == 42.0
    actions = [a.action for a in stored_audit(db) if a.risk_id == risk.risk_id]
    assert "RISK_RECALCULATED" in actions
    assert "FACTOR_ADDED" in actions
    assert "RISK_CREATED" in actions


def test_manual_recalculate_is_same_path(db):
    engine.apply_group(
        db, group_evidence("g5", "h1", ["T1021.001"]), now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    result = engine.manual_recalculate(db, risk.risk_id, now=RISK_T0)
    assert result["score"] == 42.0
    assert result["severity"] == "MEDIUM"


def test_recalculate_unknown_risk_raises(db):
    with pytest.raises(ValueError):
        engine.recalculate_entity(db, "ER-999999", now=RISK_T0)


def test_expire_factors_marks_and_audits(db):
    engine.apply_group(
        db,
        group_evidence(
            "g5", "h1", ["T1021.001"],
            observed=RISK_T0 - timedelta(days=30),
        ),
        now=RISK_T0,
    )
    risk = engine.risk_for_entity(db, "HOST", "h1")
    assert risk.score == 0.0  # already expired by the calculator
    expired = engine.expire_factors(db, now=RISK_T0)
    assert expired >= 3
    actions = [a.action for a in stored_audit(db) if a.risk_id == risk.risk_id]
    assert actions.count("FACTOR_EXPIRED") >= 3


def test_ingest_evidence_rejects_unknown_kind(db):
    with pytest.raises(ValueError):
        engine.ingest_evidence(db, [{"kind": "TAROT_CARD"}], now=RISK_T0)


def test_rerun_is_fully_idempotent(db):
    evidence = [
        group_evidence("g5", "h1", ["T1021.001"], alert_count=10),
        finding_evidence("CF-000001", ["h1"]),
    ]
    engine.ingest_evidence(db, evidence, now=RISK_T0)
    before = {f.risk_id: f.factor_id for f in stored_factors(db)}
    first_score = engine.risk_for_entity(db, "HOST", "h1").score
    engine.ingest_evidence(db, evidence, now=RISK_T0)
    after = {f.risk_id: f.factor_id for f in stored_factors(db)}
    assert before == after
    assert engine.risk_for_entity(db, "HOST", "h1").score == first_score


def test_determinism_same_evidence_same_score(db):
    engine.ingest_evidence(
        db,
        [
            group_evidence("g1", "h-a", ["T1110"]),
            group_evidence("g2", "h-a", ["T1021.001"]),
        ],
        now=RISK_T0,
    )
    engine.ingest_evidence(
        db,
        [
            group_evidence("g3", "h-b", ["T1021.001"]),
            group_evidence("g4", "h-b", ["T1110"]),
        ],
        now=RISK_T0,
    )
    a = engine.risk_for_entity(db, "HOST", "h-a")
    b = engine.risk_for_entity(db, "HOST", "h-b")
    assert a.score == b.score == 66.0


def test_recalculate_all_returns_count(db):
    engine.apply_group(
        db, group_evidence("g5", "h1", ["T1021.001"]), now=RISK_T0,
    )
    engine.apply_group(
        db, group_evidence("g6", "h2", ["T1110"]), now=RISK_T0,
    )
    count = engine.recalculate_all(db, now=RISK_T0)
    assert count == len(stored_risks(db))


def test_production_database_refused_by_name(db, monkeypatch):
    from sqlalchemy.engine import make_url

    original = config.DATABASE_URL
    monkeypatch.setattr(
        config, "DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel"
    )
    assert make_url(config.DATABASE_URL).database == config.PRODUCTION_DB_NAME
    with pytest.raises(RuntimeError):
        engine.get_or_create_risk(db, "HOST", "h1", now=RISK_T0)
    monkeypatch.setattr(config, "DATABASE_URL", original)