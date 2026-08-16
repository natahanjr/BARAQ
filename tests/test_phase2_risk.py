"""Phase-2 roadmap tests: developer-workflow detection, dynamic risk
scoring (additive deltas + roadmap scale) and the root-cause engine."""
from __future__ import annotations

import pytest

from backend.context.engine import ContextFacts
from backend.database.models import (
    Alert,
    AlertEventLink,
    Incident,
    IncidentAlertLink,
    NormalizedEvent,
)
from backend.investigation.enrichment import enrich_incident
from backend.risk.dynamic import (
    adjust_risk,
    roadmap_level,
    severity_for_level,
)
from tests.conftest import run_simulation


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

class FakeEvent:
    def __init__(self, event_id: int):
        self.event_id = event_id


def _mk_facts(processes: list[tuple[str, str]] | None = None,
              cmdline: str = "", ip: str = "", rule: str = "") -> ContextFacts:
    facts = ContextFacts(rule=rule)
    for name, path in (processes or []):
        facts.add_process(name, path)
    if cmdline:
        facts.add_command_line(cmdline)
    if ip:
        facts.add_ip(ip)
    return facts


def _mk_event(db, event_id: int, user: str = "alice", host: str = "web-01",
              org: str = "univ-a", ts: str = "2026-08-01T10:00:00",
              message: str = "event") -> NormalizedEvent:
    from datetime import datetime

    ev = NormalizedEvent(
        event_id=event_id,
        timestamp=datetime.fromisoformat(ts),
        category="Other",
        user=user,
        host=host,
        org=org,
        risk="Low",
        message=message,
    )
    db.add(ev)
    db.flush()
    return ev


def _mk_alert(db, user: str = "alice", host: str = "web-01", mitre: str = "T1078",
              rule: str = "correlation_engine", severity: str = "high",
              risk_score: float = 70.0, org: str = "univ-a") -> Alert:
    alert = Alert(
        name=f"Alert {user}",
        description="test alert",
        severity=severity,
        confidence=0.8,
        mitre_id=mitre,
        mitre_name="Valid Accounts",
        rule=rule,
        host=host,
        org=org,
        risk_score=risk_score,
        risk_level="HIGH",
        evidence=f"user '{user}' on {host}",
        correlation_id="CORR-1",
    )
    db.add(alert)
    db.flush()
    return alert


def _mk_incident(db, alert: Alert, org: str = "univ-a") -> Incident:
    from backend.investigation.dedup import correlation_key

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
# roadmap risk scale
# ---------------------------------------------------------------------------

def test_roadmap_level_thresholds():
    assert roadmap_level(0) == "LOW"
    assert roadmap_level(20) == "LOW"
    assert roadmap_level(21) == "MEDIUM"
    assert roadmap_level(40) == "MEDIUM"
    assert roadmap_level(41) == "HIGH"
    assert roadmap_level(70) == "HIGH"
    assert roadmap_level(71) == "CRITICAL"
    assert roadmap_level(100) == "CRITICAL"


def test_severity_maps_roadmap_level():
    assert severity_for_level("LOW") == "low"
    assert severity_for_level("MEDIUM") == "medium"
    assert severity_for_level("HIGH") == "high"
    assert severity_for_level("CRITICAL") == "critical"


# ---------------------------------------------------------------------------
# dynamic risk adjustments
# ---------------------------------------------------------------------------

def test_developer_tool_penalty():
    facts = _mk_facts(
        processes=[("python.exe", "C:\\dev\\venv\\Scripts\\python.exe")],
        cmdline="pip install -r requirements.txt",
    )
    result = adjust_risk(70.0, facts)
    assert result["risk"] == 30.0
    assert result["level"] == "MEDIUM"
    signals = {a["signal"] for a in result["adjustments"]}
    assert "developer_tool" in signals
    assert result["severity"] == "medium"


def test_signed_binary_penalty():
    facts = _mk_facts(processes=[("cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
                                 ("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")])
    result = adjust_risk(70.0, facts)
    assert any(a["signal"] == "signed_binary" for a in result["adjustments"])
    assert result["risk"] == 60.0


def test_unknown_binary_no_signed_penalty():
    facts = _mk_facts(processes=[("evil.exe", "C:\\Temp\\evil.exe")])
    result = adjust_risk(70.0, facts)
    assert not any(a["signal"] == "signed_binary" for a in result["adjustments"])
    assert result["risk"] == 70.0


def test_suspicious_network_bonus():
    facts = _mk_facts(processes=[("cmd.exe", "C:\\Windows\\System32\\cmd.exe")],
                      ip="203.0.113.5")
    result = adjust_risk(50.0, facts)
    assert any(a["signal"] == "suspicious_network" for a in result["adjustments"])
    assert result["risk"] == 80.0  # 50 + 30 network (signed discount withheld with external IP)


def test_localhost_ip_not_suspicious():
    facts = _mk_facts(ip="127.0.0.1")
    result = adjust_risk(50.0, facts)
    assert not any(a["signal"] == "suspicious_network" for a in result["adjustments"])


def test_persistence_bonus_from_event_id():
    facts = _mk_facts(processes=[("services.exe", "C:\\Windows\\System32\\services.exe")])
    result = adjust_risk(50.0, facts, events=[FakeEvent(7045)])
    assert any(a["signal"] == "persistence_detected" for a in result["adjustments"])
    assert result["risk"] == 65.0  # 50 - 10 signed + 25 persistence


def test_credential_access_bonus():
    facts = _mk_facts()
    result = adjust_risk(50.0, facts, events=[FakeEvent(4672)])
    assert any(a["signal"] == "credential_access" for a in result["adjustments"])
    assert result["risk"] == 85.0


def test_logon_burst_credential_bonus():
    facts = _mk_facts()
    events = [FakeEvent(4625) for _ in range(5)]
    result = adjust_risk(50.0, facts, events=events)
    assert any(a["signal"] == "credential_access" for a in result["adjustments"])


def test_known_user_penalty(db):
    _mk_event(db, 4688, user="alice")
    facts = _mk_facts(processes=[("cmd.exe", "C:\\Windows\\System32\\cmd.exe")])
    facts.add_user("alice")
    result = adjust_risk(70.0, facts, session=db)
    assert any(a["signal"] == "known_user" for a in result["adjustments"])
    assert result["risk"] == 55.0  # 70 -10 signed -5 known

    # SYSTEM never gets the known-user discount
    facts2 = _mk_facts(processes=[("cmd.exe", "C:\\Windows\\System32\\cmd.exe")])
    facts2.add_user("NT AUTHORITY\\SYSTEM")
    result2 = adjust_risk(70.0, facts2, session=db)
    assert not any(a["signal"] == "known_user" for a in result2["adjustments"])


def test_combined_developer_workflow_risk_reduced():
    facts = _mk_facts(
        processes=[("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe"),
                   ("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
        cmdline="git pull",
    )
    result = adjust_risk(70.0, facts)
    assert result["developer_workflow"] is True
    assert result["risk"] == 30.0  # 70 - 40
    assert result["severity"] == "medium"


def test_risk_clamped_to_0_100():
    dev = _mk_facts(processes=[("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
                    cmdline="pip install -r requirements.txt")
    low = adjust_risk(0.0, dev)
    assert low["risk"] == 0.0  # 0 - 40 clamped to 0
    facts = _mk_facts()
    high = adjust_risk(95.0, facts, events=[FakeEvent(4672), FakeEvent(7045)])
    assert high["risk"] == 100.0  # 95 + 60 clamped to 100


def test_no_adjustments_passthrough():
    facts = _mk_facts()
    result = adjust_risk(55.0, facts)
    assert result["risk"] == 55.0
    assert result["adjustments"] == []
    assert result["level"] == "HIGH"


# ---------------------------------------------------------------------------
# developer-workflow signal detection (feature 5)
# ---------------------------------------------------------------------------

def test_developer_signals_named_set():
    facts = _mk_facts(
        processes=[("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe"),
                   ("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
        cmdline="git pull",
    )
    wf = facts.developer_workflow()
    assert wf["detected"] is True
    assert "git_activity" in wf["signals"]
    assert "python_venv" in wf["signals"]
    assert "repository_paths" in wf["signals"]  # venv path counts as workspace


def test_vscode_activity_signal():
    facts = _mk_facts(
        processes=[("code.exe", "C:\\Users\\alice\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe")],
        cmdline="code .",
    )
    assert facts.vscode_activity is True
    assert facts.signed_binaries is True  # trusted tooling only


def test_repository_paths_signal():
    facts = _mk_facts(processes=[("node.exe", "C:\\dev\\app\\node_modules\\.bin\\node.exe")])
    assert facts.repository_paths is True


def test_notes_annotate_developer_workflow():
    facts = _mk_facts(
        processes=[("git.exe", "C:\\Program Files\\Git\\cmd\\git.exe"),
                   ("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
        cmdline="git pull",
    )
    notes = "\n".join(facts.notes())
    assert "developer workflow detected" in notes
    assert "git_activity" in notes


# ---------------------------------------------------------------------------
# root cause engine (feature 7)
# ---------------------------------------------------------------------------

def _tree(root: str = "explorer.exe", chain: list[str] | None = None) -> dict:
    return {
        "trees": [],
        "primary": None,
        "chain": [{"name": n, "pid": str(i)} for i, n in enumerate(chain or [root])],
        "aftermath": [],
        "root": root,
        "completeness": 1.0,
        "node_count": len(chain or [root]),
        "seed_found": True,
        "seed_pids": ["2"],
    }


def test_root_cause_benign_developer():
    from backend.investigation.root_cause import root_cause

    facts = _mk_facts(
        processes=[("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
                   ("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
        cmdline="python -m pytest",
    )
    risk = adjust_risk(70.0, facts)
    rc = root_cause(None, facts=facts, risk=risk,
                    tree=_tree("powershell.exe", ["powershell.exe", "python.exe"]))
    assert "powershell.exe" in rc["summary"]
    assert "python.exe" in rc["summary"]
    assert rc["chain"] == ["powershell.exe", "python.exe"]
    assert rc["assessment"] == "Likely Benign Developer Activity"
    assert rc["verdict_hint"] == "likely_benign"
    texts = [o["text"] for o in rc["observations"]]
    assert "No persistence observed" in texts
    assert "No privilege escalation observed" in texts
    assert "No suspicious network activity observed" in texts


def test_root_cause_malicious_high_risk():
    from backend.investigation.root_cause import root_cause

    facts = _mk_facts(processes=[("evil.exe", "C:\\Temp\\evil.exe")], ip="203.0.113.9")
    risk = adjust_risk(70.0, facts, events=[FakeEvent(4672), FakeEvent(7045)])
    rc = root_cause(None, facts=facts, risk=risk,
                    tree=_tree("evil.exe", ["evil.exe"]))
    assert rc["assessment"] == "Likely Malicious Activity"
    assert rc["verdict_hint"] == "likely_malicious"
    texts = [o["text"] for o in rc["observations"]]
    assert any(t.startswith("Persistence observed") for t in texts)
    assert any(t.startswith("Privilege escalation") for t in texts)
    assert any(t.startswith("Suspicious network activity") for t in texts)


def test_root_cause_developer_with_elevated_risk():
    from backend.investigation.root_cause import root_cause

    facts = _mk_facts(
        processes=[("python.exe", "C:\\dev\\app\\venv\\Scripts\\python.exe")],
        cmdline="pip install -r requirements.txt",
    )
    risk = adjust_risk(95.0, facts, events=[FakeEvent(7045)])
    rc = root_cause(None, facts=facts, risk=risk,
                    tree=_tree("powershell.exe", ["powershell.exe", "python.exe"]))
    assert rc["assessment"] == "Developer Workflow with Elevated Risk"


def test_enrichment_payload_includes_root_cause(db):
    alert = _mk_alert(db, "alice")
    incident = _mk_incident(db, alert)
    ev = _mk_event(db, 4688, user="alice")
    db.add(AlertEventLink(alert_id=alert.id, event_id=ev.id))
    db.commit()

    payload = enrich_incident(db, incident)
    assert "root_cause" in payload
    rc = payload["root_cause"]
    assert rc["root_process"]
    assert isinstance(rc["observations"], list)
    assert rc["assessment"]
    assert "risk" in rc
    assert rc["risk"]["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_simulation_alerting_with_dynamic_risk(db):
    """The full pipeline stays healthy with dynamic scoring wired in."""
    result = run_simulation(db, "brute_force")
    alerts = db.query(Alert).all()
    assert result is not None
    for alert in alerts:
        assert 0.0 <= (alert.risk_score or 0.0) <= 100.0
        assert alert.risk_level in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}