"""Phase 5 rule registry (spec 5.11, 5.13).

Deterministic registry: rule ids, versions, types and windows are pure
data - no dynamic rule loading, no ML, no probabilities. The registry is
frozen at import time; changing a rule requires a version bump.
"""
from __future__ import annotations

from backend.correlation.rules import RULES, RULES_VERSION, RULE_BY_ID

REGISTRY_VERSION = RULES_VERSION


def list_rules() -> list[dict]:
    return [
        {
            "rule_id": rule.rule_id,
            "version": rule.version,
            "title": rule.title,
            "description": rule.description,
            "correlation_type": rule.correlation_type,
            "window_key": rule.window_key,
            "priority": rule.priority,
            "chain_level": rule.chain_level,
            "emits_edges": list(rule.emits_edges),
        }
        for rule in RULES
    ]


def get_rule(rule_id: str) -> dict | None:
    rule = RULE_BY_ID.get(rule_id)
    if rule is None:
        return None
    return next(r for r in list_rules() if r["rule_id"] == rule_id)


def pair_rules():
    """All rules evaluated on group pairs, in deterministic priority order."""
    return [rule for rule in RULES if not rule.chain_level]
