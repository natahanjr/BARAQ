"""Phase 4 isolation tests (spec 4.44, 4.45).

Hard boundary: aggregation must never create incidents, modify risk,
create risk events, execute playbooks/SOAR or use ML. Everything below
asserts the counters of the v1 state stay byte-identical across the whole
aggregation lifecycle.
"""
from backend.aggregation.engine import expire_groups, process_alerts
from backend.aggregation.models import (
    BehaviorGroupAuditEvent,
    BehaviorGroupEvidence,
    BehaviorGroupMember,
    BehaviorGroupRecord,
)

from tests.aggregation.helpers import (
    GROUP_T0,
    fabricate_alerts,
    make_alerts,
    stored_groups,
    v1_counts,
)


def test_create_group_incident_count_unchanged(db):
    before = v1_counts(db)
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    assert stored_groups(db)
    assert v1_counts(db) == before


def test_add_alert_to_group_entity_risk_unchanged(db):
    before = v1_counts(db)
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert stored_groups(db)[0].alert_count == 2
    assert v1_counts(db) == before


def test_close_group_no_playbook_execution(db):
    from tests.alerting.helpers import v1_counts as alerting_v1

    before = alerting_v1(db)
    alerts = fabricate_alerts(db, [dict(minutes_ago=120.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    assert stored_groups(db)[0].status == "CLOSED"
    assert v1_counts(db) == before


def test_aggregate_100_alerts_no_incident_created(db):
    before = v1_counts(db)
    specs = [
        dict(minutes_ago=i * 0.3)
        for i in range(100)
    ]
    alerts = fabricate_alerts(db, specs)
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 100
    assert v1_counts(db) == before


def test_only_four_behavior_tables_written():
    written = {
        BehaviorGroupRecord.__tablename__,
        BehaviorGroupMember.__tablename__,
        BehaviorGroupEvidence.__tablename__,
        BehaviorGroupAuditEvent.__tablename__,
    }
    assert written == {
        "behavior_groups",
        "behavior_group_members",
        "behavior_group_evidence",
        "behavior_group_audit_events",
    }


def test_no_ml_imports_in_aggregation():
    import backend.aggregation.engine as engine

    source = open(engine.__file__, encoding="utf-8").read().lower()
    for forbidden in ("sklearn", "kmeans", "dbscan", "embeddings", "llm", "openai"):
        assert forbidden not in source