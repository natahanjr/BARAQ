"""Alert deduplication tests (spec 3.8-3.10, 3.44-3.47)."""

from __future__ import annotations

from datetime import timedelta

from backend.alerting.engine import process_detection
from tests.alerting.helpers import T0, detection, stored_alerts, stored_occurrences


def _d(**kw):
    return detection(**kw)


def test_repeated_detection_merges_into_one_alert(db):
    process_detection(db, _d(), now=T0)
    process_detection(db, _d(minutes_ago=0.1), now=T0)
    process_detection(db, _d(minutes_ago=0.2), now=T0)
    alerts = stored_alerts(db)
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 3
    assert len(alerts[0].detection_ids) == 3
    assert len(stored_occurrences(db)) == 3


def test_distinct_hosts_stay_separate(db):
    process_detection(db, _d(host="ml-host"), now=T0)
    process_detection(db, _d(host="finance-host"), now=T0)
    assert len(stored_alerts(db)) == 2


def test_distinct_users_stay_separate(db):
    process_detection(db, _d(user="alice"), now=T0)
    process_detection(db, _d(user="bob"), now=T0)
    assert len(stored_alerts(db)) == 2


def test_distinct_source_ips_stay_separate(db):
    process_detection(db, _d(source_ip="185.0.0.1"), now=T0)
    process_detection(db, _d(source_ip="41.0.0.1"), now=T0)
    assert len(stored_alerts(db)) == 2


def test_same_behavior_outside_window_new_alert(db):
    """Spec 3.10: an old alert must not absorb future behavior forever."""
    process_detection(db, _d(), now=T0)
    process_detection(db, _d(minutes_ago=0.1), now=T0 + timedelta(minutes=16))
    alerts = stored_alerts(db)
    assert len(alerts) == 2


def test_resolved_alert_never_absorbs_new_behavior(db):
    alert = process_detection(db, _d(), now=T0)
    alert.status = "RESOLVED"
    db.commit()
    process_detection(db, _d(minutes_ago=0.1), now=T0 + timedelta(minutes=1))
    assert len(stored_alerts(db)) == 2


def test_first_seen_kept_last_seen_widened(db):
    process_detection(db, _d(minutes_ago=5), now=T0)
    alert = stored_alerts(db)[0]
    first = alert.first_seen
    process_detection(db, _d(minutes_ago=0.1), now=T0)
    alert = stored_alerts(db)[0]
    assert alert.first_seen == first
    assert alert.last_seen > first


def test_dedup_window_is_detector_specific(db):
    """D005 (5 min) expires faster than D001 (15 min)."""
    process_detection(db, _d(detector_id="D005", mitre="T1486"), now=T0)
    process_detection(
        db,
        _d(detector_id="D005", mitre="T1486", minutes_ago=0.1),
        now=T0 + timedelta(minutes=6),
    )
    assert len(stored_alerts(db)) == 2


def test_evidence_preserved_per_occurrence(db):
    process_detection(db, _d(), now=T0)
    process_detection(db, _d(minutes_ago=0.1), now=T0)
    occurrences = stored_occurrences(db)
    assert len(occurrences) == 2
    for occurrence in occurrences:
        assert len(occurrence.evidence) >= 2
        assert occurrence.evidence[0]["field"] == "logon_type"


def test_occurrence_detection_ids_tracked(db):
    process_detection(db, _d(), now=T0)
    process_detection(db, _d(minutes_ago=0.1), now=T0)
    occurrences = stored_occurrences(db)
    ids = {o.detection_id for o in occurrences}
    assert len(ids) == 2
