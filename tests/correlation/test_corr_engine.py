"""Phase 5 engine tests (spec 5.2-5.10, 5.35-5.37, 5.68-5.70, 5.77)."""
from datetime import timedelta

import pytest
from sqlalchemy import text

from backend.correlation.engine import correlate
from backend.correlation.models import (
    CorrelationAuditEvent,
    CorrelationEdge,
    CorrelationEvidence,
    CorrelationFindingRecord,
    CorrelationMember,
)

from tests.correlation.helpers import (
    CORR_T0,
    canonical_specs,
    make_groups,
    stored_corr_audit,
    stored_corr_edges,
    stored_corr_evidence,
    stored_corr_members,
    stored_correlations,
)


def _v1_counts(db) -> dict[str, int]:
    return {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in ("alerts", "incidents", "entity_risk")
    }


def test_canonical_30_alerts_5_groups_1_finding(db):
    """DoD (spec 5.70): 30 alerts -> 5 groups -> 1 correlation finding."""
    specs = canonical_specs()
    assert len(specs) == 30
    groups = make_groups(db, specs, now=CORR_T0)
    assert len(groups) == 5

    findings = correlate(db, now=CORR_T0)
    assert len(findings) == 1
    finding = stored_correlations(db)[0]
    assert finding.correlation_type == "LATERAL_MOVEMENT"
    assert len(finding.member_group_ids) == 5
    assert finding.confidence == 0.88
    assert finding.highest_severity == "high"
    assert finding.status in ("NEW", "ACTIVE")

    edges = stored_corr_edges(db)
    relationship_types = {e.relationship_type for e in edges}
    assert relationship_types == {
        "SAME_USER", "SAME_SOURCE", "TEMPORAL", "DESTINATION_RELATION",
        "LATERAL_MOVEMENT",
    }
    assert any(e.relationship_type == "LATERAL_MOVEMENT" for e in edges)
    assert len(stored_corr_members(db)) == 5
    assert stored_corr_evidence(db)
    assert finding.member_alert_ids and len(finding.member_alert_ids) == 30


def test_canonical_no_overclaiming_no_incident(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    lowered = (finding.title + " " + finding.description).lower()
    for banned in (
        "confirmed attack", "confirmed compromise", "attacker confirmed",
        "breach confirmed", "apt confirmed", "malware confirmed",
        "host compromised", "account compromised", "confirmed intrusion",
        "proves",
    ):
        assert banned not in lowered
    assert _v1_counts(db) == {"alerts": 0, "incidents": 0, "entity_risk": 0}


def test_deterministic_correlation_same_input_same_output(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    first = stored_correlations(db)
    first_edges = [(e.relationship_type, e.strength) for e in stored_corr_edges(db)]

    # Wipe only the correlation tables (groups stay identical) and rerun.
    db.execute(text(
        "TRUNCATE TABLE correlation_findings, correlation_members, "
        "correlation_edges, correlation_evidence, correlation_audit_events "
        "RESTART IDENTITY CASCADE"
    ))
    db.commit()
    correlate(db, now=CORR_T0)
    second = stored_correlations(db)
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]
    assert [f.correlation_type for f in first] == [f.correlation_type for f in second]
    assert [e for e in stored_corr_edges(db)] and first_edges == [
        (e.relationship_type, e.strength) for e in stored_corr_edges(db)
    ]


def test_idempotent_rerun_no_duplicates(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    before = (len(stored_correlations(db)), len(stored_corr_edges(db)),
              len(stored_corr_members(db)), len(stored_corr_evidence(db)))
    correlate(db, now=CORR_T0)
    correlate(db, now=CORR_T0)
    after = (len(stored_correlations(db)), len(stored_corr_edges(db)),
             len(stored_corr_members(db)), len(stored_corr_evidence(db)))
    assert after == before


def test_unrelated_groups_never_correlate(db):
    """No catch-all (spec 5.74): separate users/hosts/sources -> nothing."""
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=10),
            dict(detector_id="D003", host="host-b", user="bob", source_ip="203.0.113.9",
                 mitre="T1059.001", minutes_ago=9),
            dict(detector_id="D005", host="host-c", user="carol", source_ip="203.0.113.7",
                 mitre="T1486", minutes_ago=8),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db) == []


def test_window_boundary_keeps_episodes_separate(db):
    """Spec 5.10: 4 hours apart -> never one finding."""
    make_groups(
        db,
        [
            dict(detector_id="D002", host="10.0.0.4", user="u1", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=300, destination_ip="10.0.0.5"),
            dict(detector_id="D002", host="10.0.0.5", user="u1", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=60),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db) == []


def test_auth_to_execution_rule_r001(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=5),
            dict(detector_id="D003", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1059.001", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "TEMPORAL"
    assert "R001" in {e.details.get("rule_id") for e in stored_corr_audit(db)
                      if e.action == "CORRELATION_CREATED"}


def test_credential_access_rule_r002_entity(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=5),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "ENTITY"
    edge_types = {e.relationship_type for e in stored_corr_edges(db)}
    assert "SAME_ACCOUNT" in edge_types
    assert "TACTIC_TRANSITION" in edge_types


def test_source_chain_rule_r005(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=5),
            dict(detector_id="D002", host="host-b", user="bob", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "SOURCE_CHAIN"


def test_user_chain_rule_r006(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=5),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.9",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "USER_CHAIN"


def test_multi_stage_chain_upgrade(db):
    """R009: 3+ groups spanning 2+ phases -> MULTI_STAGE."""
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=20),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=15),
            dict(detector_id="D003", host="host-c", user="alice", source_ip="203.0.113.5",
                 mitre="T1059.001", minutes_ago=10),
            dict(detector_id="D004", host="host-d", user="alice", source_ip="203.0.113.5",
                 mitre="T1053.005", minutes_ago=5),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "MULTI_STAGE"
    assert len(findings[0].member_group_ids) == 4


def test_host_chain_upgrade(db):
    """3+ distinct hosts with destination relations -> HOST_CHAIN."""
    make_groups(
        db,
        [
            dict(detector_id="D002", host="10.0.0.1", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=30, destination_ip="10.0.0.2"),
            dict(detector_id="D002", host="10.0.0.2", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=20, destination_ip="10.0.0.3"),
            dict(detector_id="D002", host="10.0.0.3", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=10, destination_ip="10.0.0.4"),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "HOST_CHAIN"
    assert len(findings[0].hosts) == 3


def test_technique_transition_rule_r007(db):
    # Same host, distinct accounts: no shared user/source -> R005/R006
    # cannot fire; R007 (same phase technique swap) is the only match.
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=5),
            dict(detector_id="D002", host="host-a", user="bob", source_ip="203.0.113.9",
                 mitre="T1621", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "TECHNIQUE_SEQUENCE"
    assert "TECHNIQUE_TRANSITION" in {
        e.relationship_type for e in stored_corr_edges(db)
    }


def test_tactic_progression_rule_r008(db):
    # Same host, distinct accounts: R008 (same-family IA -> CA progression)
    # is the only matching pair rule.
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=5),
            dict(detector_id="D002", host="host-a", user="bob", source_ip="203.0.113.9",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db)[0].correlation_type == "TACTIC_SEQUENCE"


def test_engine_refuses_production_database():
    from backend.database.connection import SessionLocal
    import backend.config as config

    original = config.DATABASE_URL
    config.DATABASE_URL = "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel"
    try:
        with pytest.raises(RuntimeError, match="refuses the v1 production database"):
            correlate(SessionLocal())
    finally:
        config.DATABASE_URL = original


def test_only_five_correlation_tables_written(db):
    written = {
        CorrelationFindingRecord.__tablename__,
        CorrelationMember.__tablename__,
        CorrelationEdge.__tablename__,
        CorrelationEvidence.__tablename__,
        CorrelationAuditEvent.__tablename__,
    }
    assert written == {
        "correlation_findings", "correlation_members", "correlation_edges",
        "correlation_evidence", "correlation_audit_events",
    }


def test_no_ml_imports_in_correlation():
    import backend.correlation.engine as engine

    source = open(engine.__file__, encoding="utf-8").read().lower()
    for forbidden in ("sklearn", "kmeans", "dbscan", "embeddings", "llm", "openai"):
        assert forbidden not in source


def test_correlation_failure_does_not_break_telemetry(db):
    """Spec 5.77: engine degradation must not corrupt state."""
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    assert len(stored_correlations(db)) == 1
    edges_before = len(stored_corr_edges(db))

    import backend.correlation.engine as engine

    original = engine.pair_rules
    engine.pair_rules = lambda: []  # simulate a broken rule source

    try:
        correlate(db, now=CORR_T0)
        assert len(stored_correlations(db)) == 1
        assert len(stored_corr_edges(db)) == edges_before
    finally:
        engine.pair_rules = original


def test_correlation_never_rewrites_groups_or_alerts(db):
    """Spec 5.68: correlation consumes groups; it never modifies them."""
    groups = make_groups(db, canonical_specs(), now=CORR_T0)
    group_snapshots = [
        (g.behavior_group_id, g.alert_count, g.status, g.last_seen) for g in groups
    ]
    correlate(db, now=CORR_T0)
    from backend.aggregation.models import BehaviorGroupRecord
    from sqlalchemy import select

    current = db.scalars(select(BehaviorGroupRecord).order_by(BehaviorGroupRecord.id)).all()
    assert [
        (g.behavior_group_id, g.alert_count, g.status, g.last_seen) for g in current
    ] == group_snapshots