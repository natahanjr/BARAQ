"""P1-1 tests: attack-chain correlation.

A campaign is a SEQUENCE of detections, not a pile of alerts: the
reconstructed chain (Discovery -> Execution -> Collection -> ...) carries
a confidence and a deterministic risk boost, persists on the incident and
re-runs every time a new alert joins the case.
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
from backend.investigation.attack_chain import apply_chain, reconstruct_chain
from backend.investigation.dedup import PROCESS_CREATE_EVENT, merge_alert


def _mk_alert(
    db,
    rule: str,
    user: str,
    host: str = "web-01",
    mitre: str = "T1059",
    severity: str = "high",
    risk_level: str = "HIGH",
    risk_score: float = 60.0,
    org: str = "univ-a",
    evidence: str = "",
    created_at: datetime | None = None,
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
        risk_score=risk_score,
        risk_level=risk_level,
        evidence=evidence or f"user '{user}' on {host}",
        correlation_id="",
        created_at=created_at or datetime.now(UTC),
    )
    db.add(alert)
    db.flush()
    return alert


def _mk_process_event(
    db, pid: int, ppid: int, name: str, ts: str, user: str, host: str = "web-01"
) -> NormalizedEvent:
    ev = NormalizedEvent(
        event_id=PROCESS_CREATE_EVENT,
        timestamp=datetime.fromisoformat(ts),
        category="Process",
        user=user,
        host=host,
        org="univ-a",
        risk="Low",
        message=f"Process {name}",
        raw_json={
            "facts": {
                "NewProcessId": str(pid),
                "ParentProcessId": str(ppid),
                "NewProcessName": name,
            }
        },
    )
    db.add(ev)
    db.flush()
    return ev


def _link(db, alert: Alert, event: NormalizedEvent):
    db.add(AlertEventLink(alert_id=alert.id, event_id=event.id))
    db.flush()


def _mk_incident(
    db, alert: Alert, host: str = "web-01", org: str = "univ-a"
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
        risk_score=60.0,
        risk_level="HIGH",
        correlation_key=correlation_key(db, alert),
        opened_at=datetime.now(UTC),
    )
    db.add(incident)
    db.flush()
    db.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
    db.flush()
    return incident


def _seed_process_tree(db, user: str, host: str = "web-01"):
    """cmd.exe (pid 100, top of chain) -> powershell.exe (200) -> archive.exe (300)."""
    return [
        _mk_process_event(db, 100, 0, "cmd.exe", "2026-08-16T10:00:00", user, host),
        _mk_process_event(
            db, 200, 100, "powershell.exe", "2026-08-16T10:05:00", user, host
        ),
        _mk_process_event(
            db, 300, 200, "archive.exe", "2026-08-16T10:10:00", user, host
        ),
    ]


def _mk_alerting(
    db, rule, user, event, host="web-01", ts="2026-08-16T10:00:00", risk_score=60.0
):
    alert = _mk_alert(
        db,
        rule,
        user,
        host=host,
        evidence=f"user '{user}' on {host}",
        risk_score=risk_score,
    )
    _link(db, alert, event)
    return alert


class TestChainReconstruction:
    def test_three_stage_chain_ordered_with_boost(self, db):
        evs = _seed_process_tree(db, "alice")
        a1 = _mk_alerting(
            db, "suspicious_powershell", "alice", evs[1], ts="2026-08-16T10:06:00"
        )
        a2 = _mk_alerting(
            db, "startup_folder", "alice", evs[1], ts="2026-08-16T10:09:00"
        )
        a3 = _mk_alerting(
            db, "archive_collection", "alice", evs[2], ts="2026-08-16T10:11:00"
        )
        incident = _mk_incident(db, a1)
        for a in (a2, a3):
            db.add(IncidentAlertLink(incident_id=incident.id, alert_id=a.id))
        db.flush()

        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == ["Execution", "Persistence", "Collection"]
        assert chain["ordered"] is True
        assert chain["cohesive_root"] is True
        assert chain["root_process"] == "cmd.exe"
        assert chain["confidence"] >= 0.8
        assert chain["risk_boost"] >= 15

    def test_disjoint_hosts_never_share_a_chain(self, db):
        evs_web = _seed_process_tree(db, "bob", host="web-01")
        evs_db = _seed_process_tree(db, "bob", host="db-02")
        a1 = _mk_alerting(db, "suspicious_powershell", "bob", evs_web[1], host="web-01")
        a2 = _mk_alerting(db, "archive_collection", "bob", evs_db[1], host="db-02")
        incident = _mk_incident(db, a1, host="web-01")
        db.add(IncidentAlertLink(incident_id=incident.id, alert_id=a2.id))
        db.flush()

        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == ["Execution", "Collection"]
        assert chain["cohesive_root"] is False
        assert chain["confidence"] < 0.8

    def test_single_stage_is_not_a_chain(self, db):
        evs = _seed_process_tree(db, "carol")
        a1 = _mk_alerting(db, "suspicious_powershell", "carol", evs[1])
        incident = _mk_incident(db, a1)

        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == []
        assert chain["risk_boost"] == 0

    def test_correlation_finding_evidence_fallback(self, db):
        alert = _mk_alert(
            db,
            "kill_chain_correlation",
            "dave",
            evidence="2 independent detections correlated for 'user:dave' "
            "(Initial Access, Execution, Exfiltration / C2)",
        )
        incident = _mk_incident(db, alert)

        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == ["Initial Access", "Execution", "Exfiltration / C2"]
        assert chain["has_terminal"] is True
        assert chain["risk_boost"] >= 15

    def test_evidence_fallback_preserves_observed_order(self, db):
        alert = _mk_alert(
            db,
            "kill_chain_correlation",
            "erin",
            evidence="correlated for 'user:erin' (Collection, Execution)",
        )
        incident = _mk_incident(db, alert)

        chain = reconstruct_chain(db, incident)
        # observed sequence is kept - the analyst sees what actually fired
        assert chain["sequence"] == ["Collection", "Execution"]
        assert chain["ordered"] is False  # deviates from canonical order


class TestApplyChain:
    def test_apply_chain_raises_risk_and_persists(self, db):
        evs = _seed_process_tree(db, "frank")
        a1 = _mk_alerting(db, "suspicious_powershell", "frank", evs[1], risk_score=50.0)
        a2 = _mk_alerting(db, "startup_folder", "frank", evs[1], risk_score=55.0)
        incident = _mk_incident(db, a1)
        db.add(IncidentAlertLink(incident_id=incident.id, alert_id=a2.id))
        db.flush()

        chain = apply_chain(db, incident)
        assert chain["sequence"] == ["Execution", "Persistence"]
        assert incident.chain_json is not None
        assert incident.chain_confidence == chain["confidence"]
        assert incident.chain_risk == chain["risk_boost"] > 0
        assert incident.risk_score >= 55.0 + chain["risk_boost"]
        assert incident.risk_score <= 100.0

    def test_apply_chain_caps_risk_at_100(self, db):
        evs = _seed_process_tree(db, "grace")
        a1 = _mk_alerting(db, "suspicious_powershell", "grace", evs[1], risk_score=99.0)
        a2 = _mk_alerting(db, "startup_folder", "grace", evs[1], risk_score=99.0)
        incident = _mk_incident(db, a1)
        db.add(IncidentAlertLink(incident_id=incident.id, alert_id=a2.id))
        db.flush()

        apply_chain(db, incident)
        assert incident.risk_score == 100.0
        assert incident.risk_level == "CRITICAL"

    def test_apply_chain_clears_when_no_chain(self, db):
        evs = _seed_process_tree(db, "heidi")
        a1 = _mk_alerting(db, "suspicious_powershell", "heidi", evs[1])
        incident = _mk_incident(db, a1)
        incident.chain_json = "{}"
        db.flush()

        apply_chain(db, incident)
        assert incident.chain_json is None
        assert incident.chain_risk == 0
        assert incident.risk_score == 60.0  # unchanged


class TestPipelineWiring:
    def test_auto_incident_gets_chain_on_creation(self, db):
        evs = _seed_process_tree(db, "ivan")
        a1 = _mk_alerting(db, "suspicious_powershell", "ivan", evs[1])
        _maybe_create_incident_helper(AlertingService(db), a1, org="univ-a")
        db.flush()

        incident = db.query(Incident).one()
        assert incident.chain_json is None  # single stage: not a chain yet
        assert incident.chain_risk == 0

    def test_grouped_campaign_ends_with_one_chained_incident(self, db):
        evs = _seed_process_tree(db, "judy")
        rules = [
            ("suspicious_powershell", "Execution", evs[1]),
            ("startup_folder", "Persistence", evs[1]),
            ("archive_collection", "Collection", evs[2]),
        ]
        for i, (rule, _stage, ev) in enumerate(rules):
            alert = _mk_alert(
                db,
                rule,
                "judy",
                host="web-01",
                risk_score=55.0,
                evidence="user 'judy' on web-01",
                created_at=datetime.now(UTC) + timedelta(minutes=i),
            )
            _link(db, alert, ev)
            _maybe_create_incident_helper(AlertingService(db), alert, org="univ-a")
            db.flush()

        incidents = db.query(Incident).all()
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.chain_json is not None
        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == ["Execution", "Persistence", "Collection"]
        assert incident.chain_confidence > 0
        assert incident.chain_risk > 0
        assert incident.risk_score >= 55.0 + incident.chain_risk

    def test_chain_grows_when_new_stage_joins(self, db):
        evs = _seed_process_tree(db, "kate")
        a1 = _mk_alerting(db, "suspicious_powershell", "kate", evs[1])
        _maybe_create_incident_helper(AlertingService(db), a1, org="univ-a")
        db.flush()
        incident = db.query(Incident).one()
        assert incident.chain_json is None

        a2 = _mk_alerting(db, "archive_collection", "kate", evs[2])
        merge_alert(db, incident, a2)
        apply_chain(db, incident)
        db.flush()

        chain = reconstruct_chain(db, incident)
        assert chain["sequence"] == ["Execution", "Collection"]
        assert incident.chain_risk > 0
        assert incident.risk_score > 60.0

    def test_merge_alert_idempotent_after_chain_risk(self, db):
        evs = _seed_process_tree(db, "liam")
        a1 = _mk_alerting(db, "suspicious_powershell", "liam", evs[1])
        a2 = _mk_alerting(db, "archive_collection", "liam", evs[2])
        incident = _mk_incident(db, a1)
        assert merge_alert(db, incident, a2) is True
        assert merge_alert(db, incident, a2) is False  # no double-count


class TestMigrationsAndApi:
    def test_incidents_table_has_chain_columns(self, db):
        from sqlalchemy import inspect

        cols = {c["name"] for c in inspect(db.get_bind()).get_columns("incidents")}
        assert {"chain_json", "chain_confidence", "chain_risk"} <= cols

    def test_incident_to_dict_exposes_chain(self, db):
        evs = _seed_process_tree(db, "mia")
        a1 = _mk_alerting(db, "suspicious_powershell", "mia", evs[1])
        incident = _mk_incident(db, a1)
        data = incident.to_dict()
        assert "chain" in data and data["chain"] is None
        assert "chain_confidence" in data
        assert "chain_risk" in data
