"""Sigma rule engine: SigmaHQ-compatible YAML detection rules."""

from backend.detection.sigma.engine import SigmaRuleEngine, load_rules_cached
from backend.detection.sigma.matcher import SigmaCondition, build_event_fields
from backend.detection.sigma.parser import SigmaRule, load_rules_dir, parse_rule

__all__ = [
    "SigmaCondition",
    "SigmaRule",
    "SigmaRuleEngine",
    "build_event_fields",
    "load_rules_cached",
    "load_rules_dir",
    "parse_rule",
]
