"""Phase-1 roadmap tests: incident dedup engine, confidence scoring,
process-tree reconstruction (GUID linkage) and investigation enrichment."""

from __future__ import annotations

from backend.database.models import (
    Alert,
    AlertEventLink,
    Incident,
    IncidentAlertLink,
    NormalizedEvent,
    ProcessRecord,
)
from backend.investigation.dedup import (
    correlation_key,
    find_open_incident,
    merge_alert,
)
from backend.investigation.enrichment import enrich_incident
from backend.investigation.process_tree import build_process_tree
from tests.conftest import run_simulation


def _mk_alert(
    db,
    user: str,
    host: str = "web-01",
    mitre: str = "T1078",
    rule: str = "correlation_engine",
    confidence: float = 0.8,
    org: str = "univ-a",
    evidence: str = "",
) -> Alert:
    alert = Alert(
        name=f"Chain {user}",
        description=f"Correlated activity for {user}",
        severity="high",
        confidence=confidence,
        mitre_id=mitre,
        mitre_name="Valid Accounts",
        rule=rule,
        host=host,
        org=org,
        risk_score=70.0,
        risk_level="HIGH",
        evidence=evidence or f"Correlated chain involving user '{user}' on {host}",
        correlation_id="CORR-1",
    )
    db.add(alert)
    db.flush()
    return alert


def _mk_incident(db, alert: Alert, org: str = "univ-a") -> Incident:
    incident = Incident(
        title=f"Incident: {alert.name}",
        description=alert.description,
        severity=alert.severity,
        status="open",
        mitre_id=alert.mitre_id,
        mitre_name=alert.mitre_name,
        host=alert.host or "",
        org=org,
        risk_score=alert.risk_score or 0.0,
        risk_level=alert.risk_level,
        confidence=alert.confidence,
        correlation_key=correlation_key(db, alert),
    )
    db.add(incident)
    db.flush()
    db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
    db.flush()
    return incident


# ---------------------------------------------------------------------------
# Dedup engine
# ---------------------------------------------------------------------------


def test_correlation_key_shape(db):
    alert = _mk_alert(db, "alice", mitre="T1110", evidence="user 'alice' on web-01")
    key = correlation_key(db, alert)
    parts = key.split("|")
    assert len(parts) == 5
    assert parts[0] == "alice"
    assert parts[1] == "web-01"
    assert parts[2] == "T1110"
    assert parts[4].isdigit()  # 30-minute window bucket


def test_same_key_merges_into_open_incident(db):
    from backend.investigation.confidence import incident_confidence

    a1 = _mk_alert(db, "alice", evidence="user 'alice' on web-01")
    incident = _mk_incident(db, a1)
    before = incident_confidence(db, incident)["score"]

    a2 = _mk_alert(db, "alice", evidence="user 'alice' on web-01 repeated")
    key = correlation_key(db, a2)
    found = find_open_incident(db, key, org="univ-a")
    assert found is not None and found.id == incident.id

    assert merge_alert(db, found, a2) is True
    db.commit()
    db.expire(incident)
    assert len(incident.alerts) == 2
    assert incident.confidence >= before  # more corroboration never lowers it

    # second merge of the same alert is a no-op
    assert merge_alert(db, found, a2) is False
    assert len(incident.alerts) == 2


def test_different_key_creates_separate_incidents(db):
    a1 = _mk_alert(db, "alice", evidence="user 'alice' on web-01")
    incident = _mk_incident(db, a1)

    a2 = _mk_alert(db, "bob", evidence="user 'bob' on web-01")
    key = correlation_key(db, a2)
    assert find_open_incident(db, key, org="univ-a") is None
    assert incident.id is not None


def test_closed_incident_not_reused(db):
    a1 = _mk_alert(db, "alice", evidence="user 'alice' on web-01")
    incident = _mk_incident(db, a1)
    incident.status = "resolved"
    db.commit()

    a2 = _mk_alert(db, "alice", evidence="user 'alice' on web-01 new wave")
    key = correlation_key(db, a2)
    assert find_open_incident(db, key, org="univ-a") is None


def test_auto_incident_via_simulation_and_dedup(db):
    """End-to-end: the correlation finding creates an incident with a
    correlation key + confidence; a re-run of the same chain merges into it."""
    run_simulation(db, "brute_force")
    incidents = db.query(Incident).all()
    assert incidents, "correlation chain should auto-create an incident"
    inc = incidents[0]
    assert inc.correlation_key
    assert "|" in inc.correlation_key
    assert 0.0 < inc.confidence <= 1.0
    assert len(inc.alerts) >= 1

    # A fresh alert matching the incident's own dimensions folds in instead
    # of duplicating.
    user, host, mitre = inc.correlation_key.split("|")[:3]
    again = _mk_alert(
        db, user, host=host, mitre=mitre, evidence=f"user '{user}' on {host}"
    )
    merged = find_open_incident(db, inc.correlation_key, org=inc.org)
    assert merged is not None and merged.id == inc.id
    merge_alert(db, merged, again)
    db.commit()
    db.expire(merged)
    assert len(merged.alerts) >= 2


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


def test_incident_confidence_scoring(db):
    a1 = _mk_alert(db, "alice", confidence=0.9, evidence="user 'alice' on web-01")
    incident = _mk_incident(db, a1)

    from backend.investigation.confidence import incident_confidence

    result = incident_confidence(db, incident)
    assert 0.0 <= result["score"] <= 1.0
    assert result["label"] in {"low", "medium", "high"}
    factors = {f["factor"] for f in result["breakdown"]}
    assert "detection quality" in factors
    assert "correlation strength" in factors
    assert "enrichment quality" in factors

    # suppression signals drag the score down
    a2 = _mk_alert(db, "carol", evidence="reputation=developer dev workflow signals")
    incident2 = _mk_incident(db, a2)
    suppressed = incident_confidence(db, incident2)
    assert suppressed["score"] < result["score"]


def test_confidence_rises_with_corroborating_alerts(db):
    from backend.investigation.confidence import incident_confidence

    a1 = _mk_alert(db, "dave", evidence="user 'dave' on web-01")
    incident = _mk_incident(db, a1)
    solo = incident_confidence(db, incident)["score"]

    for i in range(3):
        a = _mk_alert(db, "dave", evidence=f"user 'dave' on web-01 wave {i}")
        db.add(IncidentAlertLink(incident_id=incident.id, alert_id=a.id))
    db.commit()
    db.expire(incident)
    with_more = incident_confidence(db, incident)["score"]
    assert with_more > solo


# ---------------------------------------------------------------------------
# Process tree reconstruction (GUID linkage)
# ---------------------------------------------------------------------------


def _mk_event(
    db,
    event_id: int,
    facts: dict,
    ts: str,
    user: str = "alice",
    host: str = "web-01",
    org: str = "univ-a",
) -> NormalizedEvent:
    from datetime import datetime

    ev = NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(ts),
        category="Process",
        user=user,
        host=host,
        org=org,
        risk="Low",
        message=" ".join(f"{k}: {v}" for k, v in facts.items()),
        raw_json={"facts": facts, "record_number": 1, "data_integrity": {}},
    )
    db.add(ev)
    db.flush()
    return ev


def test_process_tree_guid_linking_wins_over_pid_reuse(db):
    from datetime import datetime

    parent = ProcessRecord(
        pid=100,
        ppid=1,
        name="cmd.exe",
        path="C:\\Windows\\System32\\cmd.exe",
        command_line="",
        parent_name="explorer.exe",
        user="alice",
        guid="G-PARENT",
        parent_guid="",
        is_new=False,
        observed_at=datetime.fromisoformat("2026-08-15T10:00:00+00:00"),
        org="univ-a",
    )
    child = ProcessRecord(
        pid=200,
        ppid=999,  # ppid is stale/meaningless - GUID wins
        name="whoami.exe",
        path="C:\\temp\\whoami.exe",
        command_line="whoami /priv",
        parent_name="cmd.exe",
        user="alice",
        guid="G-CHILD",
        parent_guid="G-PARENT",
        is_new=True,
        observed_at=datetime.fromisoformat("2026-08-15T10:00:01+00:00"),
        org="univ-a",
    )
    db.add_all([parent, child])
    db.commit()

    evidence = _mk_event(
        db, 4624, {"AccountName": "alice"}, "2026-08-15T10:00:01+00:00"
    )
    tree = build_process_tree(db, [evidence], org="univ-a", window_minutes=30)
    assert tree["node_count"] == 2
    nodes = {n["pid"]: n for t in tree["trees"] for n in t["nodes"]}
    assert nodes["200"]["parent_pid"] == "100", "GUID link must beat the reused ppid"
    assert nodes["200"]["guid"] == "G-CHILD"


def test_process_tree_ppid_fallback_without_guids(db):
    from datetime import datetime

    parent = ProcessRecord(
        pid=300,
        ppid=1,
        name="powershell.exe",
        path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        command_line="",
        parent_name="explorer.exe",
        user="bob",
        is_new=False,
        observed_at=datetime.fromisoformat("2026-08-15T11:00:00+00:00"),
        org="univ-a",
    )
    child = ProcessRecord(
        pid=301,
        ppid=300,
        name="whoami.exe",
        path="C:\\temp\\whoami.exe",
        command_line="whoami",
        parent_name="powershell.exe",
        user="bob",
        is_new=True,
        observed_at=datetime.fromisoformat("2026-08-15T11:00:01+00:00"),
        org="univ-a",
    )
    db.add_all([parent, child])
    db.commit()
    evidence = _mk_event(db, 4624, {"AccountName": "bob"}, "2026-08-15T11:00:01+00:00")
    tree = build_process_tree(db, [evidence], org="univ-a", window_minutes=30)
    assert tree["node_count"] == 2
    nodes = {n["pid"]: n for t in tree["trees"] for n in t["nodes"]}
    assert nodes["301"]["parent_pid"] == "300"


# ---------------------------------------------------------------------------
# Investigation enrichment
# ---------------------------------------------------------------------------


def test_enrich_incident_six_w_and_counts(db):
    add_normalized = __import__(
        "tests.fixtures", fromlist=["add_normalized"]
    ).add_normalized
    add_normalized(
        db,
        [
            {
                "source": "eventlog",
                "channel": "Security",
                "event_id": 4625,
                "org": "univ-a",
                "timestamp": "2026-08-15T12:00:00+00:00",
                "user": "alice",
                "host": "web-01",
                "message": "An account failed to log on. Account Name: alice SourceIp 10.0.0.9",
            },
            {
                "source": "eventlog",
                "channel": "Security",
                "event_id": 4104,
                "org": "univ-a",
                "timestamp": "2026-08-15T12:00:10+00:00",
                "user": "alice",
                "host": "web-01",
                "message": "PowerShell ScriptBlock text: DownloadString",
            },
        ],
        event_only=True,
    )
    _mk_event(
        db,
        4688,
        {
            "NewProcessId": "400",
            "ProcessId": "300",
            "NewProcessName": "C:\\temp\\mimikatz.exe",
        },
        "2026-08-15T12:00:05+00:00",
    )

    events = db.query(NormalizedEvent).order_by(NormalizedEvent.id).all()
    alert = _mk_alert(db, "alice", evidence="user 'alice' on web-01")
    for ev in events:
        db.add(AlertEventLink(alert_id=alert.id, event_id=ev.id))
    db.commit()

    incident = _mk_incident(db, alert)
    payload = enrich_incident(db, incident)

    assert payload["event_count"] == 3
    assert payload["related_alerts"] == 1
    assert "mimikatz.exe" in payload["processes"]
    assert payload["process_count"] >= 1
    assert payload["six_w"]["who"] == ["alice"]
    assert payload["six_w"]["where"] == ["web-01"]
    assert payload["six_w"]["when"]["first"] is not None
    assert "Credential probing" in payload["six_w"]["how"]  # 4625 step
    assert payload["six_w"]["why"]["mitre_id"] == "T1078"
    assert payload["process_tree"]["node_count"] >= 1
    assert any(t["nodes"] for t in payload["process_tree"]["trees"])


def test_enrich_incident_full_confidence(db):
    add_normalized = __import__(
        "tests.fixtures", fromlist=["add_normalized"]
    ).add_normalized
    add_normalized(
        db,
        [
            {
                "source": "eventlog",
                "channel": "Security",
                "event_id": 4688,
                "timestamp": "2026-08-15T13:00:00+00:00",
                "user": "alice",
                "host": "web-01",
                "message": "New Process Name:\tC:\\temp\\x.exe NewProcessId:\t500 ProcessId:\t400",
            },
            {
                "source": "eventlog",
                "channel": "Security",
                "event_id": 4624,
                "timestamp": "2026-08-15T13:00:01+00:00",
                "user": "alice",
                "host": "web-01",
                "message": "An account was successfully logged on. Account Name: alice",
            },
        ],
        event_only=True,
    )

    events = db.query(NormalizedEvent).order_by(NormalizedEvent.id).all()
    alert = _mk_alert(db, "alice", evidence="user 'alice' on web-01")
    for ev in events:
        db.add(AlertEventLink(alert_id=alert.id, event_id=ev.id))
    db.commit()
    incident = _mk_incident(db, alert)

    from backend.investigation.confidence import incident_confidence

    payload = enrich_incident(db, incident)
    confidence = incident_confidence(db, incident, enrichment=payload)
    assert confidence["score"] > 0.3
    assert confidence["label"] in {"low", "medium", "high"}
    assert any(f["factor"] == "enrichment quality" for f in confidence["breakdown"])
