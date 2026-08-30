"""Phase 4 regression corpus (spec 4.42): GROUP-001..GROUP-015.

Every known problem scenario is pinned here: run the alerts through the
REAL pipeline (Phase 3 alerts -> Phase 4 aggregation) and assert the
behavioral outcome. Scenarios GROUP-013/014/015 assert the isolation
boundary with v1 counts.
"""

from backend.aggregation.engine import expire_groups, process_alerts
from tests.aggregation.helpers import (
    GROUP_T0,
    fabricate_alerts,
    make_alerts,
    stored_groups,
    v1_counts,
)


def test_group_001_same_host_user_source_time_one_group(db):
    alerts = fabricate_alerts(
        db,
        [
            {"minutes_ago": 3.0},
            {"detector_id": "D002", "mitre": "T1110", "minutes_ago": 2.0},
            {"detector_id": "D001", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 3


def test_group_002_same_host_different_user_separate_groups(db):
    alerts = make_alerts(
        db,
        [
            {"user": "alice", "minutes_ago": 2.0},
            {"user": "bob", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_group_003_same_user_different_host_separate_groups(db):
    alerts = make_alerts(
        db,
        [
            {"host": "ml-host", "minutes_ago": 2.0},
            {"host": "finance-host", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_group_004_same_source_different_hosts_separate_groups(db):
    alerts = make_alerts(
        db,
        [
            {"host": "host-a", "user": "user-a", "minutes_ago": 2.0},
            {"host": "host-b", "user": "user-b", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_group_005_outside_time_window_new_group(db):
    alerts = fabricate_alerts(
        db,
        [
            {"minutes_ago": 0.0},
            {"minutes_ago": 60.0},  # beyond the 15-minute auth window
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 2
    assert groups[0].status == "CLOSED"
    assert groups[0].alert_count == 1
    assert groups[1].alert_count == 1


def test_group_006_closed_group_later_alert_new_group(db):
    alerts = fabricate_alerts(db, [{"minutes_ago": 90.0}])
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    assert stored_groups(db)[0].status == "CLOSED"

    later = fabricate_alerts(db, [{"minutes_ago": 30.0}])
    process_alerts(db, later, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 2
    assert groups[1].status == "ACTIVE"


def test_group_007_same_mitre_technique_alone_does_not_group(db):
    alerts = make_alerts(
        db,
        [
            {
                "detector_id": "D001",
                "mitre": "T1133",
                "host": "h1",
                "user": "u1",
                "source_ip": "1.1.1.1",
                "minutes_ago": 2.0,
            },
            {
                "detector_id": "D003",
                "mitre": "T1133",
                "host": "h2",
                "user": "u2",
                "source_ip": "2.2.2.2",
                "minutes_ago": 1.0,
            },
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_group_008_single_alert_valid_group(db):
    alerts = make_alerts(db, [{"minutes_ago": 1.0}])
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 1
    assert groups[0].title != ""


def test_group_009_multiple_alerts_evidence_preserved(db):
    alerts = make_alerts(
        db,
        [
            {"minutes_ago": 2.0},
            {"detector_id": "D002", "mitre": "T1110", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    from sqlalchemy import select

    from backend.aggregation.models import BehaviorGroupEvidence

    rows = db.scalars(select(BehaviorGroupEvidence)).all()
    assert len(rows) == 4
    assert {r.alert_id for r in rows} == {a.alert_id for a in alerts}


def test_group_010_timeline_chronological(db):
    alerts = fabricate_alerts(
        db,
        [
            {"minutes_ago": 3.0},
            {"detector_id": "D002", "mitre": "T1110", "minutes_ago": 2.0},
            {"detector_id": "D001", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    ids = list(group.alert_ids)
    assert ids == [a.alert_id for a in sorted(alerts, key=lambda a: a.first_seen)]


def test_group_011_cross_host_no_campaign_group(db):
    alerts = make_alerts(
        db,
        [
            {"host": "host-1", "user": "user-a", "minutes_ago": 2.0},
            {"host": "host-2", "user": "user-b", "minutes_ago": 1.0},
            {"host": "host-3", "user": "user-c", "minutes_ago": 0.5},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 3


def test_group_012_severity_does_not_escalate(db):
    alerts = make_alerts(
        db,
        [
            {"severity": "high", "minutes_ago": 2.0},
            {
                "detector_id": "D002",
                "mitre": "T1110",
                "severity": "high",
                "minutes_ago": 1.0,
            },
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    assert group.highest_severity == "high"
    assert group.highest_severity != "critical"


def test_group_013_no_incident_creation(db):
    before = v1_counts(db)
    alerts = make_alerts(db, [{"minutes_ago": 1.0}])
    process_alerts(db, alerts, now=GROUP_T0)
    assert v1_counts(db) == before


def test_group_014_no_risk_modification(db):
    before = v1_counts(db)
    alerts = make_alerts(
        db,
        [
            {"minutes_ago": 2.0},
            {"detector_id": "D002", "mitre": "T1110", "minutes_ago": 1.0},
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert v1_counts(db) == before


def test_group_015_no_soar_execution(db):
    before = v1_counts(db)
    alerts = make_alerts(db, [{"minutes_ago": 1.0}])
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    assert v1_counts(db) == before


def test_do_d_30_related_alerts_one_group(db):
    """Phase 4 DoD: 30 related alerts -> 1 group, 30 underlying occurrences."""
    specs = [{"detector_id": "D001", "minutes_ago": i * 0.4} for i in range(30)]
    alerts = fabricate_alerts(db, specs)
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 30
    assert groups[0].occurrence_count == 30


def test_do_d_unrelated_activity_stays_separate(db):
    alerts = make_alerts(
        db,
        [
            {"host": "host-a", "user": "user-a", "minutes_ago": 2.0},
            {
                "detector_id": "D005",
                "host": "host-b",
                "user": "user-b",
                "source_ip": "203.0.113.9",
                "mitre": "T1486",
                "minutes_ago": 1.0,
            },
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 2
    titles = {g.title for g in groups}
    assert "Remote Authentication Activity" in titles
    assert "Potential Data Encryption Activity" in titles
