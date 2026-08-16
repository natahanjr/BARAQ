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
from backend.detection.sigma.matcher import (
    PROCESS_FIELDS,
    SigmaCondition,
    build_event_fields,
    event_data_integrity,
)
from backend.detection.sigma.parser import SigmaRule, load_rules_dir

logger = logging.getLogger("baraq.sigma.engine")

#: Max findings emitted per rule per cycle (alerting dedups the rest).
MAX_FINDINGS_PER_RULE = 20

#: Canonical severity ladder used to demote unreliable matches.
_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

#: Sigma ``logsource.category`` -> BARAQ NormalizedEvent event IDs. Rules are
#: only evaluated against events matching their declared logsource, so e.g. a
#: ``raw_access_thread`` rule can never fire on logon/process events (a rule
#: written for Sysmon Event 25 must not match Event 4688).
_LOGSOURCE_CATEGORY_EVENT_IDS = {
    "process_creation": {1, 4688},
    "raw_access_thread": {25},
    "network_connection": {3},
    "dns_query": {22},
    "file_event": {11, 23, 26, 4656, 4660, 4663, 4662},
    "file_delete": {23, 26, 4663},
    "file_rename": {4663, 27, 28},
    "file_access": {4656, 4663},
    "file_change": {4663},
    "file_executable_detected": {1, 4688},
    "image_load": {7},
    "process_access": {10},
    "create_remote_thread": {8},
    "driver_load": {6},
    "pipe_created": {17, 18},
    "create_stream_hash": {15},
    "wmi_event": {19, 20, 21},
    "process_tampering": {10},
    "registry_set": {13, 4657, 12},
    "registry_event": {12, 13, 14, 4657},
    "registry_add": {12, 4657},
    "registry_delete": {12, 4657},
    "ps_script": {4104},
    "ps_module": {4103, 4104},
    "ps_classic_start": {400, 403},
    "ps_classic_provider_start": {400},
    "sysmon_error": {255},
    "sysmon_status": {255},
}


def _demote_severity(severity: str) -> str:
    """One step down the severity ladder (critical -> high -> ... -> info)."""
    if severity in _SEVERITY_ORDER:
        idx = _SEVERITY_ORDER.index(severity)
        return _SEVERITY_ORDER[max(0, idx - 1)] if idx > 0 else severity
    return severity


def _rule_uses_process_fields(rule: SigmaRule) -> bool:
    """True when a rule's selections depend on process identity/activity
    fields - matches are meaningless on events whose process data is
    incomplete (no image / command line captured)."""
    candidates = {f.replace("_", "").replace(".", "").replace("-", "") for f in PROCESS_FIELDS}
    for selection in rule.detection.values():
        if not isinstance(selection, dict):
            continue
        for key in selection:
            field = (
                str(key).split("|")[0].strip().lower()
                .replace("_", "").replace(".", "").replace("-", "")
            )
            if field in candidates:
                return True
    return False

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


def _logsource_event_ids(rule: SigmaRule) -> set[int] | None:
    """Event IDs allowed by the rule's declared logsource category, or None
    when the category is unknown / absent (rule stays unconstrained)."""
    category = str(rule.logsource.get("category", "")).strip().lower()
    return _LOGSOURCE_CATEGORY_EVENT_IDS.get(category)


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

    def evaluate(self, window_minutes: int, since_id: int | None = None) -> list[DetectionResult]:
        if not self.rules:
            return []
        findings: list[DetectionResult] = []
        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

        def _query_events(extra_id_cond=None):
            stmt = select(NormalizedEvent).where(
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
            if extra_id_cond is not None:
                stmt = stmt.where(extra_id_cond)
            return self.session.scalars(stmt).all()

        # Incremental mode: non-aggregation rules only see events that arrived
        # after the cursor (each event is matched exactly once, when it is
        # new). Aggregation rules keep evaluating the full window because
        # their counts legitimately span the whole detection window.
        if since_id is not None:
            delta = _query_events(NormalizedEvent.id > since_id)
            if not delta:
                return findings
            events = _query_events()
        else:
            events = _query_events()
            delta = events
        if not events:
            return findings

        # Per-rule matcher cache (conditions compiled once per cycle).
        compiled: dict[str, SigmaCondition] = {}

        # EventID universe for cheap rule-level pruning: a rule whose required
        # EventIDs do not intersect the window can never fire.
        window_ids: set[int] = {event.event_id for event in events}

        # Fields cache: build_event_fields() is pure per event - rebuild once
        # per cycle instead of once per (rule x event) pair.
        fields_cache: dict[int, dict[str, str]] = {}

        def _fields(event) -> dict[str, str]:
            fields = fields_cache.get(event.id)
            if fields is None:
                fields = build_event_fields(event)
                fields_cache[event.id] = fields
            return fields

        # Inverted rule index: per EventID -> candidate rules, so the hot loop
        # is "per event, try the rules that can possibly match this EventID"
        # instead of "per rule, scan every event". With ~2,400 rules whose
        # selections are overwhelmingly EventID-constrained this collapses the
        # per-event candidate set to a handful of rules.
        rules_by_event_id: dict[int, list[SigmaRule]] = {}
        unconstrained: list[SigmaRule] = []
        aggregation_rules: list[SigmaRule] = []
        for rule in self.rules:
            if rule.is_aggregation:
                aggregation_rules.append(rule)
                continue
            ids = _required_event_ids(rule)
            scope = _logsource_event_ids(rule)
            if ids is None:
                # No EventID constraint: the logsource scope decides which
                # events the rule may see; without either it stays global.
                if scope:
                    for eid in scope:
                        rules_by_event_id.setdefault(eid, []).append(rule)
                    continue
                unconstrained.append(rule)
                continue
            if scope:
                # The rule's own EventIDs must fall inside its logsource
                # scope; a rule written for another event type cannot match.
                ids = ids & scope
                if not ids:
                    continue
            for eid in ids:
                rules_by_event_id.setdefault(eid, []).append(rule)

        # Aggregation rules: window-wide counts (unchanged semantics). Events
        # with incomplete process data are excluded from process-field rules,
        # so a truncated batch cannot push a count over a threshold.
        for rule in aggregation_rules:
            agg = _agg_details(rule.condition)
            if agg is None:
                continue
            pre, _func, group, threshold = agg
            pre_cond = compiled.get(rule.rule_id)
            if pre_cond is None:
                pre_cond = SigmaCondition(pre)
                compiled[rule.rule_id] = pre_cond
            rule_uses_process = _rule_uses_process_fields(rule)
            scope = _logsource_event_ids(rule)
            counts: Counter[str] = Counter()
            for event in events:
                if scope and event.event_id not in scope:
                    continue
                integrity = event_data_integrity(event)
                if integrity["process_incomplete"] and rule_uses_process:
                    continue
                fields = _fields(event)
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

        # Event-level rules: match every new event against its candidate set.
        emitted: dict[str, int] = {}
        for event in delta:
            fields = _fields(event)
            integrity = event_data_integrity(event)
            candidates = unconstrained + rules_by_event_id.get(event.event_id, [])
            if not candidates:
                continue
            for rule in candidates:
                if emitted.get(rule.rule_id, 0) >= MAX_FINDINGS_PER_RULE:
                    continue
                # Exception: processes with incomplete data. Rules that
                # depend on process fields cannot be trusted on events whose
                # process data was never captured - they are skipped.
                if integrity["process_incomplete"] and _rule_uses_process_fields(rule):
                    logger.debug(
                        "Sigma: skipping '%s' for event %s - process data "
                        "incomplete (%s)",
                        rule.title, event.id, ", ".join(integrity["truncated_fields"]),
                    )
                    continue
                cond = compiled.get(rule.rule_id)
                if cond is None:
                    cond = SigmaCondition(rule.condition)
                    compiled[rule.rule_id] = cond
                if not cond.evaluate(rule.detection, fields):
                    continue
                emitted[rule.rule_id] = emitted.get(rule.rule_id, 0) + 1
                evidence = (
                    f"Sigma '{rule.title}' matched event "
                    f"{event.event_id} ({event.category}) - user "
                    f"'{event.user}': {event.message[:220]}"
                )
                severity = rule.severity
                #: Truncated process data makes the match less reliable:
                #: demote the severity so analysts are not misled.
                if integrity["process_truncated"] and severity != "info":
                    severity = _demote_severity(severity)
                    evidence += (
                        " [severity reduced: process data truncated - "
                        + ", ".join(integrity["truncated_fields"])
                        + "]"
                    )
                findings.append(
                    self._result(
                        evidence=evidence,
                        event_ids=[event.id],
                        name=rule.title,
                        severity=severity,
                        confidence=0.8,
                        mitre_id=rule.mitre_ids[0] if rule.mitre_ids else "T0000",
                        recommendation=rule.description,
                    )
                )
        return findings
