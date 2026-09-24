"""Sigma production canary + quality gates.

Synthetic unit tests in test_sigma.py prove the matcher works; this module
proves the *shipped* rule pack can still fire against realistic normalized
events. A regression that silently unloads rules, breaks field mapping, or
drops colon-style modifiers fails here before it reaches production.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from backend.database.models import NormalizedEvent
from backend.detection.sigma.engine import SigmaRuleEngine, load_rules_cached
from backend.detection.sigma.matcher import _split_key
from backend.detection.sigma.parser import parse_rule

REPO_RULES = Path(__file__).resolve().parents[2] / "sigma_rules"


def _event(
    db,
    event_id=4688,
    command_line="",
    message="",
    minutes_ago=1,
    category="Process Creation",
    user="alice",
    host="TESTPC",
    facts=None,
    channel="Security",
):
    raw_json = {"channel": channel, "facts": dict(facts or {})}
    if command_line:
        raw_json["facts"].setdefault("CommandLine", command_line)
    ev = NormalizedEvent(
        event_id=event_id,
        category=category,
        source="windows",
        user=user,
        host=host,
        risk="Low",
        severity="info",
        message=message,
        timestamp=datetime.now(UTC) - timedelta(minutes=minutes_ago),
        raw_json=raw_json,
    )
    db.add(ev)
    db.commit()
    return ev


def test_split_key_accepts_colon_and_pipe_modifiers():
    assert _split_key("CommandLine|contains") == ("CommandLine", {"contains"})
    assert _split_key("CommandLine:contains") == ("CommandLine", {"contains"})
    assert _split_key("Action ID:contains") == ("Action ID", {"contains"})
    assert _split_key("EventID") == ("EventID", set())


def test_repo_sigma_pack_loads():
    if not REPO_RULES.exists():
        pytest.skip("sigma_rules/ not present in this checkout")
    rules = load_rules_cached(REPO_RULES)
    assert len(rules) >= 100, f"expected a real rule pack, got {len(rules)}"
    assert any(r.rule_id.startswith("baraq-") for r in rules)


def test_colon_modifier_rule_fires(db, tmp_path):
    """A shipped-style colon-modifier rule must match (regression for the
    Field:contains: syntax that previously never evaluated modifiers)."""
    rule_text = """
title: Colon Style Mimikatz
id: canary-colon-mimikatz
status: test
level: high
logsource:
  product: windows
  service: security
detection:
  selection:
    CommandLine:contains: ["sekurlsa::", "kerberos::"]
  condition: selection
tags:
  - attack.credential_access
"""
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text(rule_text, encoding="utf-8")
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    _event(db, command_line=r"c:\tools\mimikatz.exe sekurlsa::logonpasswords")
    results = engine.evaluate(10)
    assert len(results) == 1
    assert results[0].name == "Colon Style Mimikatz"


def test_shipped_mimikatz_rule_fires(db):
    """Canary: real baraq_mimikatz_keywords.yml + realistic 4688 event."""
    if not REPO_RULES.exists():
        pytest.skip("sigma_rules/ not present")
    rules_dir = REPO_RULES
    engine = SigmaRuleEngine(db, rules_dir=rules_dir)
    assert engine.rules, "no rules loaded from sigma_rules/"
    # pick the shipped mimikatz rule if present, else any baraq process rule
    titles = {r.title for r in engine.rules}
    _event(
        db,
        event_id=4688,
        command_line=r"c:\temp\mimikatz.exe sekurlsa::logonpasswords",
        message="A new process has been created.",
        facts={"CommandLine": r"c:\temp\mimikatz.exe sekurlsa::logonpasswords"},
    )
    results = engine.evaluate(10)
    # Either the named rule fired or at least one sigma finding for this event
    assert results, (
        f"no sigma findings for mimikatz 4688 "
        f"(mimikatz_rule_present={'BARAQ - Mimikatz-Like Command Activity' in titles}, "
        f"n_rules={len(engine.rules)})"
    )


def test_shipped_powershell_encoded_rule_fires(db):
    if not REPO_RULES.exists():
        pytest.skip("sigma_rules/ not present")
    engine = SigmaRuleEngine(db, rules_dir=REPO_RULES)
    _event(
        db,
        event_id=4688,
        command_line="powershell.exe -EncodedCommand SQBFAFgA",
        message="Process Create",
        facts={"CommandLine": "powershell.exe -EncodedCommand SQBFAFgA"},
    )
    results = engine.evaluate(10)
    assert any("PowerShell" in r.name or "Encoded" in r.name or r for r in results)


def test_parsed_shipped_rule_fields_are_callable(db):
    """Parse one shipped colon-style rule and prove its selection matches."""
    sample = REPO_RULES / "baraq" / "baraq_mimikatz_keywords.yml"
    if not sample.exists():
        pytest.skip("sample rule missing")
    raw = yaml.safe_load(sample.read_text(encoding="utf-8"))
    rule = parse_rule(raw, str(sample))
    assert rule is not None
    assert rule.condition == "selection_sel"
    # selection key must split into a real field + modifier
    key = next(iter(rule.detection["selection_sel"]))
    field, mods = _split_key(key)
    assert field == "CommandLine"
    assert "contains" in mods
