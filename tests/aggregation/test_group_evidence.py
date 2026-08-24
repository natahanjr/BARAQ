"""Phase 4 evidence tests (spec 4.23, 4.24)."""
from backend.aggregation.engine import process_alerts
from backend.aggregation.evidence import aggregate_observables, evidence_rows, merge_observables
from backend.alerting.engine import process_detection

from tests.aggregation.helpers import GROUP_T0, make_alerts, stored_group_evidence, stored_groups
from tests.alerting.helpers import detection


def test_evidence_preserved_from_member_alerts(db):
    alerts = make_alerts(
        db,
        [
            dict(minutes_ago=2.0),
            dict(detector_id="D002", mitre="T1110", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    rows = stored_group_evidence(db)
    assert len(rows) == 4  # 2 alerts x 2 evidence items
    fields = {r.field for r in rows}
    assert "logon_type" in fields
    assert "source_ip" in fields
    alert_ids = {r.alert_id for r in rows}
    assert alert_ids == {alerts[0].alert_id, alerts[1].alert_id}


def test_evidence_never_reduced_to_multiple_alerts(db):
    alerts = make_alerts(db, [dict(minutes_ago=1.0)])
    process_alerts(db, alerts, now=GROUP_T0)
    rows = stored_group_evidence(db)
    assert rows
    assert not any(r.field == "" and r.value == "" for r in rows)
    assert not any("Multiple alerts detected" in r.reason for r in rows)


def test_observables_aggregated_unique(db):
    alerts = make_alerts(
        db,
        [
            dict(host="ml-host", user="ml-online-user", source_ip="185.100.1.5", minutes_ago=2.0),
            dict(detector_id="D002", mitre="T1110", host="ml-host",
                 user="ml-online-user", source_ip="185.100.1.5", minutes_ago=1.0),
        ],
    )
    process_alerts(db, alerts, now=GROUP_T0)
    group = stored_groups(db)[0]
    obs = group.observables
    assert obs["hosts"] == ["ml-host"]
    assert obs["users"] == ["ml-online-user"]
    assert obs["source_ips"] == ["185.100.1.5"]
    assert obs["destination_ips"] == []
    assert set(obs.keys()) >= {
        "hosts", "users", "source_ips", "destination_ips",
        "processes", "file_paths", "domains",
    }


def test_merge_observables_is_idempotent_union():
    a = {"hosts": ["h1"], "users": ["u1"]}
    b = {"hosts": ["h2"], "users": ["u1"], "domains": ["evil.example"]}
    merged = merge_observables(a, b)
    assert merged["hosts"] == ["h1", "h2"]
    assert merged["users"] == ["u1"]
    assert merged["domains"] == ["evil.example"]
    again = merge_observables(merged, b)
    assert again["hosts"] == ["h1", "h2"]


def test_observables_never_lose_alert_level_originals(db):
    """Spec 4.24: aggregation does not destroy alert-level observables."""
    alert = process_detection(db, detection())
    assert alert.observables is not None
    process_alerts(db, [alert], now=GROUP_T0)
    still = db.get(type(alert), alert.id)
    assert still.observables == alert.observables