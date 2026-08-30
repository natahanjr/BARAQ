"""P0-2 tests: alert -> incident correlation grouping.

Five related detections (different rules/techniques, same entity + window)
must fold into ONE incident; unrelated campaigns stay separate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.database.models import (
    Alert,
    AlertEventLink,
    Incident,
    IncidentAlertLink,
    NormalizedEvent,
)
from backend.detection.alerting import AlertingService, _maybe_create_incident_helper
from backend.investigation.correlation_group import find_group_incident, group_key
from backend.investigation.dedup import merge_alert
from tests.conftest import run_simulation


def _maybe_create_incident(db, alert: Alert, org: str = "univ-a"):
    return _maybe_create_incident_helper(AlertingService(db), alert, org)


def _mk_alert(
    db,
    rule: str,
    user: str,
    host: str = "web-01",
    mitre: str = "T1059",
    severity: str = "high",
    risk_level: str = "HIGH",
    org: str = "univ-a",
    evidence: str = "",
) -> Alert:
    alert = Alert(
        name=f"{rule} {user}",
        description=f"{rule} detection",
        severity=severity,
        confidence=0.8,
        mitre_id=mitre,
        mitre_name="Execution",
        rule=rule,
        host=host,
        org=org,
        risk_score=70.0,
        risk_level=risk_level,
        evidence=evidence or f"user '{user}' on {host}",
        correlation_id="",
    )
    db.add(alert)
    db.flush()
    return alert


def _mk_event(
    db,
    event_id: int,
    user: str,
    host: str = "web-01",
    facts: dict | None = None,
    ts: str = "2026-08-16T10:00:00",
) -> NormalizedEvent:
    ev = NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(ts),
        category="Process",
        user=user,
        host=host,
        org="univ-a",
        risk="Low",
        message="event",
        raw_json={"facts": facts or {}},
    )
    db.add(ev)
    db.flush()
    return ev


def _link(db, alert: Alert, event: NormalizedEvent):
    db.add(AlertEventLink(alert_id=alert.id, event_id=event.id))
    db.flush()


def _mk_incident(
    db, alert: Alert, host: str = "web-01", opened_at=None, org: str = "univ-a"
) -> Incident:
    from backend.investigation.dedup import correlation_key

    incident = Incident(
        title=f"Incident: {alert.name}",
        description="case",
        severity="high",
        status="open",
        mitre_id=alert.mitre_id,
        mitre_name="Execution",
        host=host,
        org=org,
        risk_score=70.0,
        risk_level="HIGH",
        confidence=0.8,
        correlation_key=correlation_key(db, alert),
        opened_at=opened_at or datetime.now(UTC),
    )
    db.add(incident)
    db.flush()
    db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
    db.flush()
    return incident


# ---------------------------------------------------------------------------
# group key
# ---------------------------------------------------------------------------


def test_group_key_ignores_technique_and_rule(db):
    a1 = _mk_alert(db, "python_execution", "alice", mitre="T1059.006")
    a2 = _mk_alert(db, "screen_capture", "alice", mitre="T1113")
    k1 = group_key(db, a1)
    k2 = group_key(db, a2)
    assert k1 == k2
    assert k1.startswith("group|web-01|alice|")


def test_group_key_differs_across_entities(db):
    a1 = _mk_alert(db, "python_execution", "alice", host="web-01")
    a2 = _mk_alert(db, "python_execution", "bob", host="web-01")
    assert group_key(db, a1) != group_key(db, a2)
    a3 = _mk_alert(db, "python_execution", "alice", host="db-01")
    assert group_key(db, a1) != group_key(db, a3)


# ---------------------------------------------------------------------------
# grouping lookup
# ---------------------------------------------------------------------------


def test_same_host_same_user_groups(db):
    ev = _mk_event(db, 4688, "alice")
    a1 = _mk_alert(db, "python_execution", "alice")
    _link(db, a1, ev)
    incident = _mk_incident(db, a1)

    a2 = _mk_alert(db, "suspicious_powershell", "alice", mitre="T1059.001")
    found = find_group_incident(db, a2, org="univ-a")
    assert found is not None and found.id == incident.id


def test_same_host_same_root_process_groups(db):
    facts = {
        "NewProcessId": "100",
        "ParentProcessId": "50",
        "NewProcessName": "C:\\tools\\python.exe",
    }
    parent = {
        "NewProcessId": "50",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    ev = _mk_event(db, 4688, "alice", facts=facts)
    db.add(_mk_event(db, 4688, "alice", facts=parent))
    db.flush()
    a1 = _mk_alert(db, "python_execution", "alice")
    _link(db, a1, ev)
    incident = _mk_incident(db, a1)

    ev2 = _mk_event(db, 4688, "bob", facts=facts)
    db.add(_mk_event(db, 4688, "bob", facts=parent))
    db.flush()
    a2 = _mk_alert(db, "python_execution", "bob")
    _link(db, a2, ev2)
    found = find_group_incident(db, a2, org="univ-a")
    assert found is not None and found.id == incident.id


def test_different_host_never_groups(db):
    a1 = _mk_alert(db, "python_execution", "alice", host="web-01")
    incident = _mk_incident(db, a1, host="web-01")

    a2 = _mk_alert(db, "python_execution", "alice", host="db-01")
    found = find_group_incident(db, a2, org="univ-a")
    assert found is None
    assert incident.id is not None


def test_stale_incident_not_reused(db):
    a1 = _mk_alert(db, "python_execution", "alice")
    _mk_incident(db, a1, opened_at=datetime.now(UTC) - timedelta(hours=3))

    a2 = _mk_alert(db, "suspicious_powershell", "alice")
    found = find_group_incident(db, a2, org="univ-a")
    assert found is None


def test_resolved_incident_not_reused(db):
    a1 = _mk_alert(db, "python_execution", "alice")
    incident = _mk_incident(db, a1)
    incident.status = "resolved"
    db.commit()

    a2 = _mk_alert(db, "suspicious_powershell", "alice")
    found = find_group_incident(db, a2, org="univ-a")
    assert found is None


# ---------------------------------------------------------------------------
# end-to-end: five related detections -> one incident
# ---------------------------------------------------------------------------


def test_five_related_alerts_fold_into_one_incident(db):
    ev = _mk_event(db, 4688, "alice")
    a1 = _mk_alert(db, "python_execution", "alice", mitre="T1059.006")
    _link(db, a1, ev)
    _maybe_create_incident(db, a1)
    db.commit()

    for rule, mitre in (
        ("suspicious_powershell", "T1059.001"),
        ("account_discovery", "T1087"),
        ("screen_capture", "T1113"),
        ("archive_collection", "T1560"),
    ):
        a = _mk_alert(db, rule, "alice", mitre=mitre)
        _maybe_create_incident(db, a)
        db.commit()

    incidents = db.query(Incident).filter(Incident.host == "web-01").all()
    assert len(incidents) == 1, f"expected 1 grouped incident, got {len(incidents)}"
    assert len(incidents[0].alerts) == 5


def test_low_risk_alert_stays_alert_only(db):
    ev = _mk_event(db, 4688, "alice")
    a1 = _mk_alert(db, "python_execution", "alice", risk_level="LOW")
    _link(db, a1, ev)
    _maybe_create_incident(db, a1)
    db.commit()
    assert db.query(Incident).count() == 0


def test_dev_workflow_alert_no_incident(db):
    ev = _mk_event(db, 4688, "alice")
    a1 = _mk_alert(
        db,
        "python_execution",
        "alice",
        risk_level="HIGH",
        evidence="user 'alice' on web-01\nContext:\n  context verdict: strong developer-workflow context",
    )
    _link(db, a1, ev)
    _maybe_create_incident(db, a1)
    db.commit()
    assert db.query(Incident).count() == 0


def test_simulation_pipeline_healthy_with_grouping(db):
    result = run_simulation(db, "brute_force")
    assert result is not None
    incidents = db.query(Incident).all()
    for inc in incidents:
        assert len(inc.alerts) >= 1


def test_grouping_merges_via_merge_alert_semantics(db):
    """Folding into a group behaves like a dedup merge (no duplicate links)."""
    ev = _mk_event(db, 4688, "alice")
    a1 = _mk_alert(db, "python_execution", "alice")
    _link(db, a1, ev)
    incident = _mk_incident(db, a1)

    a2 = _mk_alert(db, "screen_capture", "alice", mitre="T1113")
    assert find_group_incident(db, a2, org="univ-a") is not None
    assert merge_alert(db, incident, a2) is True
    db.commit()
    db.expire(incident)
    assert len(incident.alerts) == 2
    assert merge_alert(db, incident, a2) is False  # idempotent
