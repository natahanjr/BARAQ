"""Phase 4 engine tests (spec 4.4-4.6, 4.46-4.48)."""
from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from backend.aggregation.engine import expire_groups, process_alerts
from backend.aggregation.models import BehaviorGroupMember, BehaviorGroupRecord
from backend.alerting.engine import process_detection

from tests.aggregation.helpers import (
    GROUP_T0,
    make_alerts,
    stored_group_audit,
    stored_groups,
    stored_members,
    v1_counts,
)
from tests.alerting.helpers import detection


def test_full_pipeline_auth_episode(db):
    """4.49: RDP + failed logon + successful logon -> one group.

    The Phase 3 pipeline already dedups the two D001 detections (same
    detector, same identity, in-window), so this yields 2 distinct alerts
    / 3 occurrences in one group - dedup + aggregation working together.
    """
    alerts = make_alerts(
        db,
        [
            dict(detector_id="D001", mitre="T1133", minutes_ago=2.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0),
            dict(detector_id="D001", mitre="T1133", minutes_ago=0.5),
        ],
    )
    groups = process_alerts(db, alerts, now=GROUP_T0)
    assert len(groups) == 1
    group = stored_groups(db)[0]
    assert group.behavior_group_id.startswith("BG-")
    assert group.title == "Remote Authentication Activity"
    assert group.alert_count == 2
    assert group.occurrence_count == 3
    assert group.highest_severity == "high"
    assert group.status == "ACTIVE"
    assert group.first_seen <= group.last_seen
    assert set(group.alert_ids) == {a.alert_id for a in alerts}


def test_deterministic_grouping_same_input_same_output(db):
    for _ in range(2):
        alerts = make_alerts(
            db,
            [
                dict(minutes_ago=2.0),
                dict(detector_id="D002", mitre="T1110", minutes_ago=1.0),
            ],
        )
        process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 2


def test_idempotent_rerun_no_duplicate_memberships(db):
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=1.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=0.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    process_alerts(db, alerts, now=GROUP_T0)
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 2
    assert len(stored_members(db)) == 2
    assert groups[0].occurrence_count == 2


def test_single_alert_group_is_valid(db):
    """4.20: single-alert groups are valid."""
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 1
    assert groups[0].alert_count == 1


def test_group_title_and_description_do_not_overclaim(db):
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    assert "confirmed" not in group.title.lower()
    assert "attack" not in group.title.lower()
    assert "compromised" not in group.title.lower()
    assert group.description
    assert "alert" in group.description


def test_suppressed_alerts_never_aggregated(db):
    from backend.alerting.lifecycle import transition
    from backend.alerting.models import AlertRecord
    from backend.alerting.suppression import create_rule

    alerts = make_alerts(db, [dict(minutes_ago=2.0)])
    rule = create_rule(
        db, policy_id="SUP-1", reason="legacy noise",
        expires_at=GROUP_T0 + timedelta(days=1), now=GROUP_T0,
    )
    db.commit()
    rule.scope = {"host": "workstation-42"}
    db.commit()
    suppressed = make_alerts(
        db,
        [dict(minutes_ago=1.0, host="workstation-42")],
    )
    assert len(suppressed) == 0  # the Phase 3 engine already suppressed it
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 1


def test_partial_unique_index_blocks_duplicate_live_groups(db):
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    duplicate = BehaviorGroupRecord(
        behavior_group_id="BG-999999",
        group_fingerprint=group.group_fingerprint,
        title="dup",
        description="",
        status="ACTIVE",
        first_seen=GROUP_T0,
        last_seen=GROUP_T0,
        alert_count=1,
        occurrence_count=1,
        created_at=GROUP_T0,
        updated_at=GROUP_T0,
    )
    db.add(duplicate)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()


def test_closed_groups_release_the_fingerprint(db):
    from tests.aggregation.helpers import fabricate_alerts

    alerts = fabricate_alerts(db, [dict(minutes_ago=120.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    assert stored_groups(db)[0].status == "CLOSED"

    later = fabricate_alerts(db, [dict(minutes_ago=30.0)])
    process_alerts(db, later, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_engine_never_touches_v1_state(db):
    before = v1_counts(db)
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    expire_groups(db, now=GROUP_T0)
    after = v1_counts(db)
    assert after == before


def test_engine_refuses_production_db_by_name(monkeypatch):
    import backend.config as config

    monkeypatch.setattr(
        config, "DATABASE_URL",
        "postgresql+psycopg://postgres@127.0.0.1:55432/sentinel",
    )
    from backend.aggregation.engine import _ensure_not_production_db

    with pytest.raises(RuntimeError, match="refuses"):
        _ensure_not_production_db()


def test_membership_reason_and_score_recorded(db):
    alerts = make_alerts(db, [dict(minutes_ago=2.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    member = stored_members(db)[0]
    assert "same host" in member.membership_reason
    assert "same user" in member.membership_reason
    assert member.membership_score == 1.0


def test_confidence_bounded_and_deterministic(db):
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0, confidence=0.91),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0, confidence=0.82),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    assert 0.0 <= group.confidence <= 1.0
    assert group.confidence == round(min(1.0, 0.91 + 0.15), 4)  # strongest + consistency


def test_severity_never_escalated(db):
    """4.28: 2 HIGH alerts -> highest_severity HIGH, never CRITICAL."""
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0, severity="high"),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0, severity="high"),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert stored_groups(db)[0].highest_severity == "high"


def test_unrelated_alerts_stay_separate(db):
    """4.50: RDP ml-host + PowerShell finance-host + ransomware backup-host."""
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0),
            dict(detector_id="D003", host="finance-host", user="bob",
                 source_ip="203.0.113.7", mitre="T1059.001", minutes_ago=1.0),
            dict(detector_id="D005", host="backup-host", user="system",
                 source_ip="203.0.113.9", mitre="T1486", minutes_ago=0.5),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    groups = stored_groups(db)
    assert len(groups) == 3
    assert all(g.alert_count == 1 for g in groups)
    assert {g.title for g in groups} == {
        "Remote Authentication Activity",
        "Suspicious Execution Activity",
        "Potential Data Encryption Activity",
    }


def test_different_users_same_host_do_not_group(db):
    """4.37: host A + user A/B/C -> separate groups."""
    alerts = make_alerts(
        db,
        [
            dict(user="alice", source_ip="203.0.113.5", minutes_ago=2.0),
            dict(user="bob", source_ip="203.0.113.9", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_cross_host_source_does_not_group(db):
    """4.36: same source, different hosts -> separate groups."""
    alerts = make_alerts(
        db,
        [
            dict(host="host-a", user="user-a", minutes_ago=2.0),
            dict(host="host-b", user="user-b", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    assert len(stored_groups(db)) == 2


def test_alert_reference_integrity(db):
    """4.46: every membership references a real alert."""
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    member = stored_members(db)[0]
    alert = db.get(type(alerts[0]), alerts[0].id)
    assert member.alert_id == alert.alert_id
    group = stored_groups(db)[0]
    assert group.alert_ids == [alert.alert_id]