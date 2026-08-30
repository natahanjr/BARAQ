"""Sigma rule parsing (SigmaHQ-compatible YAML -> structured rules).

Supports the core Sigma 1.0 schema: title, id, level, logsource, detection
(selections + boolean condition), fields, falsepositives and tags (attack.*
mapping to MITRE ATT&CK). Selections may be mappings of field->value or bare
keyword lists; values support modifiers (contains, startswith, endswith, re,
all, base64, cidr, null).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("baraq.sigma.parser")

LEVEL_SEVERITY = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}

#: Sigma condition keywords that turn a rule into an aggregation (window-wide).
AGGREGATE_OPS = (">", ">=", "<", "<=", "==", "=")


@dataclass
class SigmaRule:
    """One parsed Sigma rule (normalized for the matcher)."""

    title: str
    rule_id: str
    level: str
    severity: str
    detection: dict[str, Any]
    condition: str
    tags: list[str] = field(default_factory=list)
    description: str = ""
    status: str = ""
    logsource: dict[str, str] = field(default_factory=dict)
    fields: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    source_file: str = ""

    @property
    def mitre_ids(self) -> list[str]:
        out = []
        for tag in self.tags:
            t = tag.strip().lower()
            if t.startswith("attack."):
                part = t.split("attack.", 1)[1]
                if part.startswith("t") and len(part) > 1:
                    out.append(part.upper())
        return out

    @property
    def is_aggregation(self) -> bool:
        return "|" in self.condition


def parse_rule(raw: dict, source_file: str = "") -> SigmaRule | None:
    """Parse one raw YAML mapping into a SigmaRule, or None if unusable."""
    title = str(raw.get("title", "")).strip()
    detection = raw.get("detection") or {}
    condition = str(detection.get("condition", "")).strip()
    if not title or not detection or not condition:
        return None

    level = str(raw.get("level", "medium")).strip().lower()
    rule_id = str(raw.get("id", "")).strip().lower() or f"no-id-{abs(hash(title))}"
    tags = [str(t) for t in (raw.get("tags") or [])]
    logsource = raw.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}

    selections = {k: v for k, v in detection.items() if k != "condition"}
    return SigmaRule(
        title=title,
        rule_id=rule_id,
        level=level,
        severity=LEVEL_SEVERITY.get(level, "medium"),
        detection=selections,
        condition=condition,
        tags=tags,
        description=str(raw.get("description", "")).strip(),
        status=str(raw.get("status", "")).strip(),
        logsource={str(k): str(v) for k, v in logsource.items()},
        fields=[str(f) for f in (raw.get("fields") or [])],
        falsepositives=[str(f) for f in (raw.get("falsepositives") or [])],
        source_file=source_file,
    )


def load_rules_dir(rules_dir: Path) -> list[SigmaRule]:
    """Load and parse every *.yml / *.yaml under a directory tree."""
    if not rules_dir.exists():
        return []
    rules: list[SigmaRule] = []
    for path in sorted(rules_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".yml", ".yaml"):
            continue
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        except yaml.YAMLError as exc:
            logger.warning("Sigma: skipped unparsable rule %s (%s)", path, exc)
            continue
        if not isinstance(raw, dict):
            continue
        rule = parse_rule(raw, source_file=str(path))
        if rule is None:
            logger.debug("Sigma: skipped non-detection file %s", path)
            continue
        rules.append(rule)
    return rules
