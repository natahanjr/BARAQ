"""Phase 5 regression corpus (spec 5.62, 5.70): CORR-001..CORR-025 + DoD.

Every known-problem scenario is pinned here: behavior groups -> REAL
correlation engine -> asserted outcome. CORR-020..CORR-025 pin the
isolation boundary (v1 counters untouched).
"""
from sqlalchemy import text

from backend.aggregation.engine import expire_groups, process_alerts
from backend.correlation.engine import correlate, expire_correlations

from tests.correlation.helpers import (
    CORR_T0,
    canonical_specs,
    make_groups,
    stored_corr_edges,
    stored_corr_evidence,
    stored_corr_members,
    stored_correlations,
)
from tests.aggregation.helpers import fabricate_alerts


def _v1_counts(db) -> dict[str, int]:
    return {
        t: db.execute(text(f'SELECT COUNT(*) FROM "{t}"')).scalar()
        for t in ("alerts", "incidents", "entity_risk")
    }


def test_corr_001_same_user_same_source_temporal_one_finding(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=3),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert len(stored_correlations(db)) == 1


def test_corr_002_temporal_only_two_relationships(db):
    # Same host, same window, no shared user/source and no matching rule
    # (empty technique => no progression claim) -> never correlates.
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=2),
            dict(detector_id="D002", host="host-a", user="bob", source_ip="203.0.113.9",
                 mitre="", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db) == []


def test_corr_003_outside_window_separate_findings(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=400),
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db) == []


def test_corr_004_auth_then_execution_is_temporal_finding(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=4),
            dict(detector_id="D003", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1059.001", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db)[0].correlation_type == "TEMPORAL"


def test_corr_005_execution_then_credential_is_technique_sequence(db):
    make_groups(
        db,
        [
            dict(detector_id="D003", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1059.001", minutes_ago=4),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db)[0].correlation_type == "TECHNIQUE_SEQUENCE"


def test_corr_006_external_access_credential_is_entity(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=4),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db)[0].correlation_type == "ENTITY"


def test_corr_007_three_group_progression_is_multi_stage(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=15),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=10),
            dict(detector_id="D003", host="host-c", user="alice", source_ip="203.0.113.5",
                 mitre="T1059.001", minutes_ago=5),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    assert finding.correlation_type == "MULTI_STAGE"
    assert len(finding.member_group_ids) == 3


def test_corr_008_three_host_chain_is_host_chain(db):
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
    assert stored_correlations(db)[0].correlation_type == "HOST_CHAIN"


def test_corr_009_lateral_edge_wins_chain_type(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="10.0.0.1", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=10, destination_ip="10.0.0.2"),
            dict(detector_id="D002", host="10.0.0.2", user="alice", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=5, destination_ip="10.0.0.3"),
            dict(detector_id="D003", host="10.0.0.3", user="alice", source_ip="10.0.0.2",
                 mitre="T1021.001", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    assert finding.correlation_type == "LATERAL_MOVEMENT"
    assert "LATERAL_MOVEMENT" in {e.relationship_type for e in stored_corr_edges(db)}


def test_corr_010_confidence_bounded_and_deterministic(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    assert 0.0 <= finding.confidence <= 1.0
    assert finding.confidence == 0.88


def test_corr_011_single_pair_minimum_confidence_floor(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=3),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.9",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    finding = stored_correlations(db)[0]
    assert finding.confidence >= 0.2


def test_corr_012_rerun_is_idempotent(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    for _ in range(3):
        correlate(db, now=CORR_T0)
    assert len(stored_correlations(db)) == 1
    assert len(stored_corr_members(db)) == 5
    assert len(stored_corr_edges(db)) == len(stored_corr_edges(db))


def test_corr_013_evidence_and_membership_reasons_preserved(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    reasons = {m.membership_reason for m in stored_corr_members(db)}
    assert any("R005" in r for r in reasons)
    assert any("R001" in r for r in reasons)
    fields = {e.field for e in stored_corr_evidence(db)}
    assert "rule_reason" in fields


def test_corr_014_audit_trail_covers_creation(db):
    from tests.correlation.helpers import stored_corr_audit

    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    actions = {e.action for e in stored_corr_audit(db)}
    assert "CORRELATION_CREATED" in actions
    assert "GROUP_ADDED" in actions
    assert "EDGE_CREATED" in actions


def test_corr_015_no_banned_claims_in_any_finding(db):
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    for finding in stored_correlations(db):
        lowered = (finding.title + " " + finding.description).lower()
        for banned in (
            "confirmed attack", "confirmed compromise", "breach confirmed",
            "apt confirmed", "host compromised", "proves",
        ):
            assert banned not in lowered


def test_corr_016_fingerprint_unique_per_live_finding(db):
    make_groups(
        db,
        [
            dict(detector_id="D002", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=2),
            dict(detector_id="D002", host="host-b", user="alice", source_ip="203.0.113.5",
                 mitre="T1110", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    fingerprints = [f.fingerprint for f in stored_correlations(db)]
    assert len(fingerprints) == len(set(fingerprints))


def test_corr_017_quiet_then_closed_lifecycle(db):
    from datetime import timedelta

    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    expire_correlations(db, now=CORR_T0 + timedelta(hours=2))
    finding = stored_correlations(db)[0]
    assert finding.status == "QUIET"
    expire_correlations(db, now=CORR_T0 + timedelta(hours=5))
    assert stored_correlations(db)[0].status == "CLOSED"


def test_corr_018_closed_finding_does_not_reopen(db):
    from datetime import timedelta

    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    expire_correlations(db, now=CORR_T0 + timedelta(hours=8))
    assert stored_correlations(db)[0].status == "CLOSED"
    make_groups(
        db,
        [
            dict(detector_id="D002", host="10.0.0.9", user="u-r1", source_ip="198.51.100.9",
                 mitre="T1110", minutes_ago=0),
        ],
        now=CORR_T0 + timedelta(hours=9),
    )
    correlate(db, now=CORR_T0 + timedelta(hours=9))
    assert stored_correlations(db)[0].status == "CLOSED"
    assert len(stored_correlations(db)) == 2


def test_corr_019_unrelated_episodes_never_correlate(db):
    make_groups(
        db,
        [
            dict(detector_id="D001", host="host-a", user="alice", source_ip="203.0.113.5",
                 mitre="T1133", minutes_ago=3),
            dict(detector_id="D005", host="backup-host", user="system",
                 source_ip="203.0.113.9", mitre="T1486", minutes_ago=2),
            dict(detector_id="D003", host="finance-host", user="bob",
                 source_ip="203.0.113.7", mitre="T1059.001", minutes_ago=1),
        ],
        now=CORR_T0,
    )
    correlate(db, now=CORR_T0)
    assert stored_correlations(db) == []


def test_corr_020_no_incidents_created(db):
    before = _v1_counts(db)
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    expire_correlations(db, now=CORR_T0)
    assert stored_correlations(db)
    assert _v1_counts(db) == before


def test_corr_021_no_risk_mutation(db):
    before = _v1_counts(db)
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    assert _v1_counts(db) == before


def test_corr_022_no_playbook_or_soar_execution(db):
    before = _v1_counts(db)
    make_groups(db, canonical_specs(), now=CORR_T0)
    correlate(db, now=CORR_T0)
    assert _v1_counts(db) == before


def test_corr_023_no_ml_in_correlation_path():
    import backend.correlation.engine as engine

    source = open(engine.__file__, encoding="utf-8").read().lower()
    for forbidden in ("sklearn", "kmeans", "dbscan", "embeddings", "llm", "openai"):
        assert forbidden not in source


def test_corr_024_groups_never_modified_by_correlation(db):
    from sqlalchemy import select

    from backend.aggregation.models import BehaviorGroupRecord

    make_groups(db, canonical_specs(), now=CORR_T0)
    snapshot = [
        (g.behavior_group_id, g.alert_count, g.status)
        for g in db.scalars(select(BehaviorGroupRecord)).all()
    ]
    correlate(db, now=CORR_T0)
    current = [
        (g.behavior_group_id, g.alert_count, g.status)
        for g in db.scalars(select(BehaviorGroupRecord)).all()
    ]
    assert current == snapshot


def test_corr_025_scale_30_groups_linear_correlation(db):
    # 30 unrelated groups -> 0 findings; 30 related groups -> 1 finding.
    specs = [
        dict(detector_id="D002", host=f"10.0.0.{i % 5 + 1}", user="alice",
             source_ip="198.51.100.9", mitre="T1110", minutes_ago=i * 0.4)
        for i in range(30)
    ]
    make_groups(db, specs, now=CORR_T0)
    correlate(db, now=CORR_T0)
    assert len(stored_correlations(db)) == 1
    assert len(stored_correlations(db)[0].member_group_ids) == 5


def test_dod_30_alerts_5_groups_1_finding(db):
    """Definition of done (spec 5.70): 30 alerts -> 5 groups -> 1 finding."""
    specs = canonical_specs()
    assert len(specs) == 30
    alerts = fabricate_alerts(db, specs)
    groups = process_alerts(db, alerts, now=CORR_T0)
    assert len(groups) == 5
    correlate(db, now=CORR_T0)
    findings = stored_correlations(db)
    assert len(findings) == 1
    assert findings[0].correlation_type == "LATERAL_MOVEMENT"
    assert findings[0].confidence == 0.88
    assert len(findings[0].member_group_ids) == 5
    assert len(findings[0].member_alert_ids) == 30