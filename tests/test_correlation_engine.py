"""Tests for the declarative YAML correlation engine."""

from __future__ import annotations

from datetime import UTC

import pytest

from backend.database.models import Alert
from backend.detection.correlation_engine import (
    CorrelationEngine,
    CorrelationStage,
    load_correlation_rules,
    parse_correlation_yaml,
)


def _mk_alert(
    db, rule: str, tactic: str, host: str = "WS-01", evidence: str = ""
) -> Alert:
    alert = Alert(
        name=f"{rule} detection",
        description="test",
        severity="medium",
        status="open",
        confidence=0.7,
        score=4,
        evidence=evidence or f"User 'tester' on {host}",
        rule=rule,
        host=host,
        org="",
        event_count=1,
        risk_score=50.0,
        risk_level="MEDIUM",
        mitre_id="T0000",
        mitre_tactic=tactic,
    )
    db.add(alert)
    db.flush()
    return alert


SAMPLE_YAML = {
    "name": "brute_force_admin_escalation",
    "description": "Brute force then privilege escalation on one host.",
    "enabled": True,
    "severity": "critical",
    "confidence": 0.9,
    "mitre_id": "T1078",
    "window_minutes": 60,
    "group_by": "host",
    "match": "all",
    "stages": [
        {
            "label": "Credential Access",
            "rules": ["brute_force"],
            "tactics": ["Credential Access"],
        },
        {
            "label": "Privilege Escalation",
            "rules": ["privilege_escalation"],
            "tactics": ["Privilege Escalation"],
        },
    ],
}


def test_parse_correlation_yaml():
    spec = parse_correlation_yaml(SAMPLE_YAML, source="test.yml")
    assert spec.name == "brute_force_admin_escalation"
    assert spec.group_by == "host"
    assert spec.match == "all"
    assert len(spec.stages) == 2
    assert spec.stages[0].rules == ["brute_force"]
    assert spec.stages[0].tactics == ["Credential Access"]
    assert spec.stages[1].matches_alert(
        _mk_alert_proxy("privilege_escalation", "Privilege Escalation")
    )


def _mk_alert_proxy(rule: str, tactic: str) -> object:
    class _A:
        def __init__(self):
            self.rule = rule
            self.mitre_tactic = tactic

    return _A()


def test_parse_invalid_yaml_raises():
    with pytest.raises(ValueError):
        parse_correlation_yaml(
            {"name": "x", "group_by": "banana", "stages": [{"label": "s"}]}
        )
    with pytest.raises(ValueError):
        parse_correlation_yaml({"name": "x", "stages": []})
    with pytest.raises(ValueError):
        parse_correlation_yaml(
            {"name": "x", "stages": [{"label": "s"}], "match": "sometimes"}
        )


def test_stage_match_by_rule_and_tactic():
    stage_rules = CorrelationStage("s", rules=["brute_force"])
    stage_tactics = CorrelationStage("s", tactics=["Credential Access"])
    alert = _mk_alert_proxy("brute_force", "Credential Access")
    assert stage_rules.matches_alert(alert)
    assert stage_tactics.matches_alert(alert)
    other = _mk_alert_proxy("usb_device", "Lateral Movement")
    assert not stage_rules.matches_alert(other)
    assert not stage_tactics.matches_alert(other)


def test_correlation_engine_all_stages_matched(db):
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    _mk_alert(db, "privilege_escalation", "Privilege Escalation", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(SAMPLE_YAML, source="test.yml")]

    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "correlation_engine"
    assert f.severity == "critical"
    assert "2/2 stages" in f.evidence
    assert "WS-01" in f.evidence
    assert "brute_force" in f.evidence


def test_correlation_engine_missing_stage_no_finding(db):
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(SAMPLE_YAML, source="test.yml")]
    assert engine.evaluate(window_minutes=60) == []


def test_correlation_engine_match_any_fires_on_one_stage(db):
    yaml = dict(SAMPLE_YAML, match="any")
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(yaml, source="test.yml")]
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert "1/2 stages" in findings[0].evidence


def test_correlation_engine_one_alert_never_covers_two_stages(db):
    """P0: a single alert matching multiple stages (rule in one, tactic in
    another) must only satisfy ONE stage - otherwise one event fabricates an
    entire attack chain. Rule matches win over tactic-only matches."""
    # rule=privilege_escalation matches stage 2 by rule AND stage 1's
    # "Credential Access" tactic. Old engine counted it for both -> fake 2/2.
    _mk_alert(db, "privilege_escalation", "Credential Access", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(SAMPLE_YAML, source="test.yml")]
    assert engine.evaluate(window_minutes=60) == []  # stage 1 unmatched

    # a real second stage alert on the same host then completes the chain
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert "2/2 stages" in findings[0].evidence


def test_correlation_ids_share_daily_sequence(db):
    """Correlated findings carry traceable CORR-YYYYMMDD-NNNN ids."""
    yaml = dict(SAMPLE_YAML, match="any")
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(yaml, source="test.yml")]
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    cid = findings[0].correlation_id
    assert cid.startswith("CORR-")
    assert len(cid.split("-")) == 3  # CORR-YYYYMMDD-NNNN


def test_correlation_engine_group_by_host_isolates_entities(db):
    _mk_alert(db, "brute_force", "Credential Access", host="WS-01")
    _mk_alert(db, "privilege_escalation", "Privilege Escalation", host="WS-02")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(SAMPLE_YAML, source="test.yml")]
    assert engine.evaluate(window_minutes=60) == []  # stages on different hosts


def test_correlation_engine_group_by_user(db):
    yaml = dict(SAMPLE_YAML, group_by="user")
    _mk_alert(
        db, "brute_force", "Credential Access", host="WS-01", evidence="User 'alice'"
    )
    _mk_alert(
        db,
        "privilege_escalation",
        "Privilege Escalation",
        host="WS-02",
        evidence="User 'alice'",
    )
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(yaml, source="test.yml")]
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    assert "2/2 stages" in findings[0].evidence


def test_load_correlation_rules_from_directory(db, tmp_path):
    (tmp_path / "rule_a.yml").write_text(
        """
name: test_rule
description: A test correlation rule.
enabled: true
severity: high
mitre_id: T1021
window_minutes: 30
group_by: host
match: any
stages:
  - label: Lateral
    tactics: [Lateral Movement]
""",
        encoding="utf-8",
    )
    (tmp_path / "disabled_rule.yml.disabled").write_text(
        "name: ignored\nstages: []\n", encoding="utf-8"
    )
    specs = load_correlation_rules(tmp_path)
    assert len(specs) == 1
    assert specs[0].name == "test_rule"


def test_load_correlation_rules_skips_missing_dir():
    import tempfile
    from pathlib import Path

    assert load_correlation_rules(Path(tempfile.gettempdir()) / "no_such_dir_xyz") == []


def test_disabled_rules_are_skipped(db, tmp_path):
    (tmp_path / "off.yml").write_text(
        """
name: off_rule
enabled: false
stages:
  - label: X
    rules: [brute_force]
""",
        encoding="utf-8",
    )
    specs = load_correlation_rules(tmp_path)
    assert specs == []


MULTI_SOURCE_YAML = {
    "name": "brute_force_then_admin_events",
    "description": "Event-stream brute force followed by an admin alert.",
    "enabled": True,
    "severity": "high",
    "window_minutes": 60,
    "group_by": "host",
    "match": "all",
    "stages": [
        {
            "label": "Brute Force",
            "source": "events",
            "events": {"event_ids": [4625], "min_count": 3, "min_risk": "Medium"},
        },
        {
            "label": "Admin Escalation",
            "source": "alerts",
            "rules": ["privilege_escalation"],
        },
    ],
}


def _mk_event(
    db,
    event_id: int,
    host: str = "WS-01",
    risk: str = "Medium",
    severity: str = "medium",
) -> None:
    from datetime import datetime

    from backend.database.models import NormalizedEvent

    db.add(
        NormalizedEvent(
            event_id=event_id,
            category="Authentication",
            source="eventlog",
            user="alice",
            host=host,
            org="",
            risk=risk,
            severity=severity,
            message=f"Logon failure for user alice (event {event_id})",
            timestamp=datetime.now(UTC),
            data_integrity="complete",
        )
    )
    db.flush()


def test_parse_event_stage_yaml():
    spec = parse_correlation_yaml(MULTI_SOURCE_YAML, source="ms.yml")
    assert spec.stages[0].source == "events"
    assert spec.stages[0].events.event_ids == [4625]
    assert spec.stages[0].events.min_count == 3
    assert spec.stages[0].events.min_risk == "medium"
    assert spec.stages[1].source == "alerts"


def test_parse_event_stage_requires_condition():
    with pytest.raises(ValueError):
        parse_correlation_yaml(
            {
                "name": "x",
                "stages": [{"label": "s", "source": "events", "events": {}}],
            }
        )


def test_parse_alert_stage_requires_rules_or_tactics():
    with pytest.raises(ValueError):
        parse_correlation_yaml({"name": "x", "stages": [{"label": "s", "rules": []}]})


def test_event_stage_matches_raw_events(db):
    spec = parse_correlation_yaml(MULTI_SOURCE_YAML, source="ms.yml")
    from backend.database.models import NormalizedEvent

    for _ in range(4):
        _mk_event(db, 4625)
    _mk_event(db, 4688)  # non-matching event_id
    events = db.query(NormalizedEvent).all()
    matched = [e for e in events if spec.stages[0].matches_event(e)]
    assert len(matched) == 4


def test_event_stage_risk_and_severity_conditions(db):
    from backend.database.models import NormalizedEvent
    from backend.detection.correlation_engine import EventConditions

    cond = EventConditions(event_ids=[4625], min_risk="Medium")
    _mk_event(db, 4625, risk="Low")
    _mk_event(db, 4625, risk="High")
    low, high = db.query(NormalizedEvent).all()
    assert not cond.matches(low)
    assert cond.matches(high)

    sev = EventConditions(severity=["critical"])
    _mk_event(db, 4625, risk="High", severity="critical")
    crit = (
        db.query(NormalizedEvent).filter(NormalizedEvent.severity == "critical").one()
    )
    assert sev.matches(crit)
    _mk_event(db, 4625, risk="High", severity="low")
    low_sev = db.query(NormalizedEvent).filter(NormalizedEvent.severity == "low").one()
    assert not sev.matches(low_sev)


def test_engine_joins_events_and_alerts_on_entity(db):
    for _ in range(4):
        _mk_event(db, 4625, host="WS-01")
    _mk_event(db, 4625, host="WS-02")  # different host - not enough to qualify there
    _mk_alert(db, "privilege_escalation", "Privilege Escalation", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(MULTI_SOURCE_YAML, source="ms.yml")]
    findings = engine.evaluate(window_minutes=60)
    assert len(findings) == 1
    f = findings[0]
    assert "2/2 stages" in f.evidence
    assert "events" in f.evidence
    assert "WS-01" in f.evidence


def test_engine_event_stage_min_count_not_met(db):
    _mk_event(db, 4625, host="WS-01")
    _mk_event(db, 4625, host="WS-01")
    _mk_alert(db, "privilege_escalation", "Privilege Escalation", host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(MULTI_SOURCE_YAML, source="ms.yml")]
    assert engine.evaluate(window_minutes=60) == []  # only 2/3 required events


def test_engine_alert_stage_missing_no_finding(db):
    for _ in range(4):
        _mk_event(db, 4625, host="WS-01")
    engine = CorrelationEngine(db)
    engine.specs = [parse_correlation_yaml(MULTI_SOURCE_YAML, source="ms.yml")]
    assert engine.evaluate(window_minutes=60) == []


def test_load_multi_source_sample_rules():
    specs = load_correlation_rules()
    names = {s.name for s in specs}
    assert "brute_force_admin_escalation_events" in names
