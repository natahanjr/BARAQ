"""Sigma rule engine tests - parsing, matching, event-ID filtering and
aggregations against synthetic normalized events."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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


def _event(
    db,
    event_id=4688,
    command_line="",
    message="",
    minutes_ago=1,
    category="Process Creation",
    integrity=None,
):
    raw_json = {"channel": "Security", "facts": {"CommandLine": command_line}}
    if integrity is not None:
        raw_json["data_integrity"] = integrity
    ev = NormalizedEvent(
        event_id=event_id,
        category=category,
        source="windows",
        user="testuser",
        host="TESTPC",
        risk="Low",
        severity="info",
        message=message,
        timestamp=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        raw_json=raw_json,
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


IMAGE_RULE = """
title: Suspicious Image Only
id: 9f4c5d6e-7f8a-4b9c-0d1e-2f3a4b5c6d7e
status: test
level: high
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
    Image|endswith: mimikatz.exe
  condition: selection
tags:
  - attack.credential_access
"""


def test_sigma_exception_for_incomplete_process_data(db, tmp_path):
    """Rules that depend on process fields must not fire on events whose
    process data was never captured (data-integrity exception)."""
    rules_dir = _write_rules(tmp_path, [IMAGE_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(
        db,
        command_line="",
        integrity={
            "complete": False,
            "truncated_fields": ["process_data"],
            "reasons": [
                "no process image or command line captured for a process event"
            ],
        },
    )
    assert engine.evaluate(10) == []


def test_sigma_exception_allows_non_process_rules(db, tmp_path):
    """The incomplete-data exception only suppresses rules that reference
    process fields; EventID-only rules still evaluate."""
    rules_dir = _write_rules(tmp_path, [AGGREGATION_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    for _ in range(3):
        _event(
            db,
            command_line="",
            integrity={
                "complete": False,
                "truncated_fields": ["process_data"],
                "reasons": [
                    "no process image or command line captured for a process event"
                ],
            },
        )
    results = engine.evaluate(10)
    assert len(results) == 1
    assert "3 matching event(s)" in results[0].evidence


def test_sigma_demotes_severity_when_process_truncated(db, tmp_path):
    """A rule that matches on truncated process data still fires, but the
    severity is demoted because the evidence is unreliable."""
    rules_dir = _write_rules(tmp_path, [MIMIKATZ_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(
        db,
        command_line="mimikatz.exe sekurlsa::logonpasswords...",
        integrity={
            "complete": False,
            "truncated_fields": ["CommandLine"],
            "reasons": [
                "structured field CommandLine ends mid-value (truncation marker or partial path)"
            ],
        },
    )
    results = engine.evaluate(10)
    assert len(results) == 1
    assert results[0].severity == "medium"  # demoted from high
    assert "severity reduced" in results[0].evidence


def test_sigma_complete_data_keeps_severity(db, tmp_path):
    rules_dir = _write_rules(tmp_path, [MIMIKATZ_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(
        db,
        command_line=r"c:\tools\mimikatz.exe sekurlsa::logonpasswords",
        integrity={
            "complete": True,
            "truncated_fields": [],
            "reasons": [],
        },
    )
    results = engine.evaluate(10)
    assert len(results) == 1
    assert results[0].severity == "high"


NULL_IMAGE_RULE = """
title: Missing Image Field
id: 5a6b7c8d-9e0f-4a1b-8c2d-3e4f5a6b7c8d
status: test
level: medium
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4688
  filter_main_null:
    Image: null
  condition: selection and not 1 of filter_main_*
falsepositives:
  - None
"""


def test_sigma_null_filter_matches_missing_field(db, tmp_path):
    """``Image: null`` must match events where the field is absent entirely,
    not only events where it is empty - otherwise every event without image
    data trips the rule."""
    rules_dir = _write_rules(tmp_path, [NULL_IMAGE_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    ev = _event(db, command_line="cmd.exe /c whoami")
    ev.raw_json = {"channel": "Security", "facts": {"CommandLine": "cmd.exe /c whoami"}}
    db.commit()
    assert engine.evaluate(10) == []


RAW_DISK_RULE = """
title: Raw Disk Access By Uncommon Tools
id: 6b7c8d9e-0f1a-4b2c-9d3e-4f5a6b7c8d9e
status: test
level: low
logsource:
  product: windows
  category: raw_access_thread
detection:
  selection:
    EventID: 25
  condition: selection
falsepositives:
  - Likely
"""


def test_sigma_logsource_scopes_rule_to_event_type(db, tmp_path):
    """A rule declared for ``raw_access_thread`` (Sysmon Event 25) must not
    fire on process-creation events - logsource category is a scope, not a
    hint."""
    rules_dir = _write_rules(tmp_path, [RAW_DISK_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(db, command_line="cmd.exe /c whoami")
    assert engine.evaluate(10) == []


def test_sigma_logsource_scopes_rule_without_eventid(db, tmp_path):
    """A rule with no EventID selection but a process_creation logsource is
    indexed under the process event IDs, not evaluated globally."""
    rules_dir = _write_rules(
        tmp_path,
        [
            NULL_IMAGE_RULE.replace(
                "  selection:\n    EventID: 4688\n",
                "  selection:\n    CommandLine|contains: whoami\n",
            )
        ],
    )
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(db, event_id=4625, command_line="whoami")
    assert engine.evaluate(10) == []


PUBLIC_IP_RULE = """
title: Failed Logon From Public IP
id: 7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f
status: test
level: medium
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  filter_main_local_ranges:
    IpAddress|cidr:
      - '10.0.0.0/8'
      - '127.0.0.0/8'
      - '172.16.0.0/12'
      - '192.168.0.0/16'
  condition: selection and not 1 of filter_main_*
falsepositives:
  - None
"""


def test_sigma_ipaddress_aliases_to_source_ip(db, tmp_path):
    """``IpAddress`` (Sigma/Sysmon spelling) must resolve to BARAQ's
    ``source_ip`` fact so CIDR filters exclude private logon sources."""
    rules_dir = _write_rules(tmp_path, [PUBLIC_IP_RULE])
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    raw_json = {
        "channel": "Security",
        "facts": {"source_ip": "192.168.1.12", "logon_type": "3"},
    }
    ev = NormalizedEvent(
        event_id=4625,
        category="Authentication",
        source="windows",
        user="testuser",
        host="TESTPC",
        risk="Low",
        severity="info",
        message="failed logon",
        timestamp=datetime.now(UTC) - timedelta(minutes=1),
        raw_json=raw_json,
    )
    db.add(ev)
    db.commit()
    assert engine.evaluate(10) == []
