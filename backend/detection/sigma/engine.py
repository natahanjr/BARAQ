"""Sigma rule engine - runs SigmaHQ YAML rules as BARAQ detection rules.

Loads every *.yml / *.yaml under the configured rules directory (default
``sigma_rules/``, populated by ``scripts/sigma_pull.py``), parses them with
the Sigma matcher, and evaluates them against the normalized event window.

Performance: rules are cached per directory fingerprint; a per-rule EventID
index prefilters candidates so only plausible rules are matched per event.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from backend.config import SIGMA_RULES_DIR
from backend.database.models import NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult
from backend.detection.sigma.matcher import SigmaCondition, build_event_fields
from backend.detection.sigma.parser import SigmaRule, load_rules_dir

logger = logging.getLogger("baraq.sigma.engine")

#: Max findings emitted per rule per cycle (alerting dedups the rest).
MAX_FINDINGS_PER_RULE = 20

_cache: dict[tuple, list[SigmaRule]] = {}


def _dir_fingerprint(rules_dir: Path) -> tuple:
    if not rules_dir.exists():
        return ("missing", 0, 0)
    newest = 0
    count = 0
    for path in rules_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in (".yml", ".yaml"):
            count += 1
            newest = max(newest, path.stat().st_mtime)
    return (str(rules_dir), newest, count)


def load_rules_cached(rules_dir: Path) -> list[SigmaRule]:
    fingerprint = _dir_fingerprint(rules_dir)
    if fingerprint[2] == 0:
        _cache.pop("sigma", None)
        return []
    cached = _cache.get("sigma")
    if cached and cached[0] == fingerprint:
        return cached[1]
    rules = load_rules_dir(rules_dir)
    _cache["sigma"] = (fingerprint, rules)
    logger.info("Sigma: loaded %d rule(s) from %s", len(rules), rules_dir)
    return rules


def _required_event_ids(rule: SigmaRule) -> set[int] | None:
    """EventID constraints from a rule's selections, or None when unconstrained."""
    event_ids: set[int] | None = None
    for selection in rule.detection.values():
        if not isinstance(selection, dict):
            continue
        for key, value in selection.items():
            parts = str(key).split("|")
            if parts[0].lower() != "eventid":
                continue
            raw_values = value if isinstance(value, list) else [value]
            ids = {int(v) for v in raw_values if str(v).lstrip("-").isdigit()}
            if event_ids is None:
                event_ids = set()
            event_ids |= ids
    return event_ids


def _agg_details(condition: str) -> tuple[str, str, str, int] | None:
    """Parse 'sel | count[()][(field)][ by group] OP N' -> (pre, func, group, N)."""
    m = re.match(
        r"^\s*([A-Za-z0-9_* .\-()]+?)\s*\|\s*"
        r"count\s*(?:\(\s*([A-Za-z0-9_.]*)\s*\))?\s*"
        r"(?:by\s+([A-Za-z0-9_.]+))?\s*"
        r"(>|>=|<|<=|==|=)\s*(\d+)\s*$",
        condition,
        re.IGNORECASE,
    )
    if not m:
        return None
    return m.group(1).strip(), m.group(2) or "", m.group(3) or "", int(m.group(5))


class SigmaRuleEngine(BaseRule):
    rule_id = "sigma_rules"
    name = "Sigma Community Rules"
    description = (
        "Community-written SigmaHQ detection rules evaluated against the "
        "normalized event stream (3000+ rules from the Sigma project)."
    )
    severity = "medium"
    confidence = 0.8
    mitre_id = "T0000"
    recommendation = ""

    def __init__(self, session, rules_dir: Path | None = None, org: str | None = None):
        super().__init__(session, org)
        self.rules_dir = Path(rules_dir or SIGMA_RULES_DIR)
        self.rules = load_rules_cached(self.rules_dir)

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        if not self.rules:
            return []
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        events = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()
        if not events:
            return findings

        # Per-rule matcher cache (conditions compiled once per cycle).
        compiled: dict[str, SigmaCondition] = {}

        for rule in self.rules:
            if rule.is_aggregation:
                agg = _agg_details(rule.condition)
                if agg is None:
                    continue
                pre, _func, group, threshold = agg
                pre_cond = compiled.get(rule.rule_id)
                if pre_cond is None:
                    pre_cond = SigmaCondition(pre)
                    compiled[rule.rule_id] = pre_cond
                counts: Counter[str] = Counter()
                for event in events:
                    fields = build_event_fields(event)
                    if pre_cond.evaluate(rule.detection, fields):
                        key = str(fields.get(group.lower(), "")) if group else ""
                        counts[key] += 1
                op = re.search(r"(>|>=|<|<=|==|=)\s*(\d+)\s*$", rule.condition.strip())
                op_str = op.group(1) if op else ">"

                def _cmp(count: int) -> bool:
                    if op_str == ">":
                        return count > threshold
                    if op_str == ">=":
                        return count >= threshold
                    if op_str == "<":
                        return count < threshold
                    if op_str == "<=":
                        return count <= threshold
                    return count == threshold

                hits = [k for k, c in counts.items() if _cmp(c)]
                if not hits:
                    continue
                top = max(hits, key=lambda k: counts[k])
                findings.append(
                    self._result(
                        evidence=(
                            f"Sigma '{rule.title}' - {counts[top]} matching event(s)"
                            + (f" for '{top}'" if group else "")
                            + f" (threshold {rule.condition.split('|')[-1].strip()})."
                        ),
                        event_ids=[],
                        name=rule.title,
                        severity=rule.severity,
                        confidence=min(0.95, 0.65 + min(counts[top], 10) * 0.03),
                        mitre_id=rule.mitre_ids[0] if rule.mitre_ids else "T0000",
                        recommendation=rule.description,
                    )
                )
                continue

            ids = _required_event_ids(rule)
            cond = compiled.get(rule.rule_id)
            if cond is None:
                cond = SigmaCondition(rule.condition)
                compiled[rule.rule_id] = cond
            emitted = 0
            for event in events:
                if ids is not None and event.event_id not in ids:
                    continue
                fields = build_event_fields(event)
                if not cond.evaluate(rule.detection, fields):
                    continue
                emitted += 1
                findings.append(
                    self._result(
                        evidence=(
                            f"Sigma '{rule.title}' matched event "
                            f"{event.event_id} ({event.category}) - user "
                            f"'{event.user}': {event.message[:220]}"
                        ),
                        event_ids=[event.id],
                        name=rule.title,
                        severity=rule.severity,
                        confidence=0.8,
                        mitre_id=rule.mitre_ids[0] if rule.mitre_ids else "T0000",
                        recommendation=rule.description,
                    )
                )
                if emitted >= MAX_FINDINGS_PER_RULE:
                    break
        return findings
