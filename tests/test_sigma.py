"""Sigma rule engine tests - parsing, matching, event-ID filtering and
aggregations against synthetic normalized events."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import yaml

from backend.database.models import NormalizedEvent
from backend.detection.sigma.engine import SigmaRuleEngine
from backend.detection.sigma.parser import parse_rule

MIMIKATZ_RULE = """
title: Mimikatz CommandLine
id: 7f2f1b6a-3c4d-4e5f-8a9b-0c1d2e3f4a5b
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    CommandLine|contains: mimikatz
  condition: selection
falsepositives:
  - None
tags:
  - attack.credential_access
  - attack.t1003
"""

AGGREGATION_RULE = """
title: Many Process Creations
id: 8a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c6d
status: test
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
  condition: selection | count() > 2
falsepositives:
  - None
tags:
  - attack.discovery
"""


def _write_rules(tmp_path, rules):
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    for i, text in enumerate(rules):
        (rules_dir / f"rule_{i}.yml").write_text(text, encoding="utf-8")
    return rules_dir


def _event(db, event_id=4688, command_line="", message="", minutes_ago=1,
           category="Process Creation"):
    ev = NormalizedEvent(
        event_id=event_id,
        category=category,
        source="windows",
        user="testuser",
        host="TESTPC",
        risk="Low",
        severity="info",
        message=message,
        timestamp=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        raw_json={"channel": "Security", "facts": {"CommandLine": command_line}},
    )
    db.add(ev)
    db.commit()
    return ev


def test_parse_rule_basics():
    rule = parse_rule(yaml.safe_load(MIMIKATZ_RULE), "test.yml")
    assert rule is not None
    assert rule.title == "Mimikatz CommandLine"
    assert rule.severity == "high"
    assert rule.mitre_ids == ["T1003"]
    assert not rule.is_aggregation


def test_sigma_simple_match(db, tmp_path):
    rules_dir = _write_rules(tmp_path, [MIMIKATZ_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(db, command_line=r"c:\tools\mimikatz.exe sekurlsa::logonpasswords")
    _event(db, command_line="notepad.exe")
    results = engine.evaluate(10)
    assert len(results) == 1
    assert results[0].name == "Mimikatz CommandLine"
    assert results[0].severity == "high"
    assert results[0].mitre_id == "T1003"
    assert results[0].event_ids


def test_sigma_eventid_filter(db, tmp_path):
    """A rule pinned to EventID 4688 must ignore other event IDs."""
    rules_dir = _write_rules(tmp_path, [MIMIKATZ_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(db, event_id=4104, command_line="mimikatz sekurlsa::logonpasswords")
    assert engine.evaluate(10) == []


def test_sigma_aggregation(db, tmp_path):
    rules_dir = _write_rules(tmp_path, [AGGREGATION_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    for _ in range(3):
        _event(db, command_line="cmd.exe /c whoami")
    results = engine.evaluate(10)
    assert len(results) == 1
    assert "3 matching event(s)" in results[0].evidence


def test_sigma_aggregation_below_threshold(db, tmp_path):
    rules_dir = _write_rules(tmp_path, [AGGREGATION_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    for _ in range(2):
        _event(db, command_line="cmd.exe /c whoami")
    assert engine.evaluate(10) == []
