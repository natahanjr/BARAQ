"""Declarative correlation engine - multi-stage detection via YAML.

Analysts define correlation rules as YAML files (no Python code): each rule
declares a window, a grouping key (host / user / ip), an ordered list of
stages and a match mode. The engine evaluates open alerts **and raw
telemetry events** inside the window, groups them per entity, and raises a
higher-severity finding when the declared stage combination is observed on
the same entity - the BARAQ equivalent of correlation searches
(and multi-source joins: one stage can consume alerts, another can consume
raw event streams, and both share the same entity key).

Schema (one YAML file per rule):

.. code-block:: yaml

    name: suspicious_persistence_chain
    description: Initial access followed by persistence on the same host.
    enabled: true
    severity: high
    confidence: 0.8
    mitre_id: T1071
    window_minutes: 60
    group_by: host            # host | user | ip | none
    match: all                # all | any
    stages:
      - label: Initial Access
        source: alerts        # alerts (default) | events | any
        rules: [email_phishing, malware_file]
        tactics: [Initial Access]
      - label: Persistence
        source: events
        events:
          event_ids: [13]             # any of these Windows Event IDs
          categories: [Process]       # any of these normalized categories
          sources: [win-sysmon]       # any of these collectors
          min_risk: Medium            # Low | Medium | High | Critical
          severity: [high]            # any of these severities
          min_count: 3                # minimum matching events for the stage

For alert stages, ``rules`` / ``tactics`` are optional; a stage matches when
any open alert in the window belongs to one of its rule ids **or** one of
its tactics. ``source: events`` stages consume raw telemetry instead.
``match: any`` fires on the first matched stage; ``match: all`` requires
every stage to have at least one match on the same entity.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.config import CORRELATION_RULES_DIR
from backend.database.models import Alert, NormalizedEvent
from backend.detection.rules.base import BaseRule, DetectionResult

logger = logging.getLogger("baraq.detection.correlation")

_GROUP_KEYS = ("host", "user", "ip", "none")
_LEVELS = ("info", "low", "medium", "high", "critical")
_RISK_LEVELS = ("low", "medium", "high", "critical")
_SOURCES = ("alerts", "events", "any")

_EVENT_ID_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(r"(?:User|account) '([^']+)'")


@dataclass
class EventConditions:
    """Raw-event matcher for a correlation stage."""

    event_ids: list[int] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    min_risk: str = ""
    severity: list[str] = field(default_factory=list)
    min_count: int = 1

    def matches(self, event: NormalizedEvent) -> bool:
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        if self.categories and event.category not in self.categories:
            return False
        if self.sources and event.source not in self.sources:
            return False
        if self.min_risk and (event.risk or "Low").lower() not in self._risk_ge():
            return False
        return not (
            self.severity
            and (event.severity or "").lower() not in [s.lower() for s in self.severity]
        )

    def _risk_ge(self) -> list[str]:
        base = self.min_risk.lower()
        return _RISK_LEVELS[_RISK_LEVELS.index(base) :] if base in _RISK_LEVELS else []

    def to_dict(self) -> dict:
        return {
            "event_ids": self.event_ids,
            "categories": self.categories,
            "sources": self.sources,
            "min_risk": self.min_risk,
            "severity": self.severity,
            "min_count": self.min_count,
        }


@dataclass
class CorrelationStage:
    """One step of a declarative correlation rule."""

    label: str
    rules: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    source: str = "alerts"
    events: EventConditions = field(default_factory=EventConditions)

    def matches_alert(self, alert: Alert) -> bool:
        if self.source == "events":
            return False
        if self.rules and alert.rule in self.rules:
            return True
        return bool(self.tactics and alert.mitre_tactic in self.tactics)

    def matches_event(self, event: NormalizedEvent) -> bool:
        if self.source == "alerts":
            return False
        return self.events.matches(event)


@dataclass
class CorrelationSpec:
    """A parsed YAML correlation rule."""

    name: str
    description: str = ""
    enabled: bool = True
    severity: str = "high"
    confidence: float = 0.8
    mitre_id: str = "T1071"
    recommendation: str = ""
    window_minutes: int = 60
    group_by: str = "host"
    match: str = "all"
    stages: list[CorrelationStage] = field(default_factory=list)

    def matches_any_alert(self, alert: Alert) -> bool:
        return any(stage.matches_alert(alert) for stage in self.stages)

    def matches_any_event(self, event: NormalizedEvent) -> bool:
        return any(stage.matches_event(event) for stage in self.stages)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "severity": self.severity,
            "confidence": self.confidence,
            "mitre_id": self.mitre_id,
            "window_minutes": self.window_minutes,
            "group_by": self.group_by,
            "match": self.match,
            "stages": [
                {
                    "label": s.label,
                    "source": s.source,
                    "rules": s.rules,
                    "tactics": s.tactics,
                    "events": s.events.to_dict(),
                }
                for s in self.stages
            ],
        }


def _to_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _parse_events(data: dict | None, source: str) -> EventConditions:
    data = data or {}
    if not isinstance(data, dict):
        raise ValueError(f"[{source}] stage 'events' must be a mapping")
    event_ids = data.get("event_ids") or []
    try:
        event_ids = [int(v) for v in event_ids]
    except (TypeError, ValueError):
        raise ValueError(f"[{source}] stage event_ids must be integers")
    min_risk = str(data.get("min_risk", "")).lower()
    if min_risk and min_risk not in _RISK_LEVELS:
        raise ValueError(f"[{source}] min_risk must be one of {_RISK_LEVELS}")
    severity = [s.lower() for s in _to_list(data.get("severity"))]
    unknown = [s for s in severity if s not in _LEVELS]
    if unknown:
        raise ValueError(
            f"[{source}] stage severity contains unknown level(s): {unknown}"
        )
    min_count = max(1, int(data.get("min_count", 1)))
    if not (
        event_ids
        or data.get("categories")
        or data.get("sources")
        or min_risk
        or severity
    ):
        raise ValueError(
            f"[{source}] event stage needs at least one of event_ids / "
            "categories / sources / min_risk / severity"
        )
    return EventConditions(
        event_ids=event_ids,
        categories=_to_list(data.get("categories")),
        sources=_to_list(data.get("sources")),
        min_risk=min_risk,
        severity=severity,
        min_count=min_count,
    )


def parse_correlation_yaml(data: dict, source: str = "inline") -> CorrelationSpec:
    """Parse a raw YAML mapping into a validated CorrelationSpec."""
    stages = []
    for raw in data.get("stages") or []:
        if not isinstance(raw, dict):
            raise ValueError(
                f"[{source}] stage must be a mapping, got {type(raw).__name__}"
            )
        stage_source = str(raw.get("source", "alerts")).lower()
        if stage_source not in _SOURCES:
            raise ValueError(f"[{source}] stage source must be one of {_SOURCES}")
        if stage_source == "alerts" and not (raw.get("rules") or raw.get("tactics")):
            raise ValueError(f"[{source}] alert stage needs rules and/or tactics")
        stages.append(
            CorrelationStage(
                label=str(raw.get("label", "Stage")),
                rules=_to_list(raw.get("rules")),
                tactics=_to_list(raw.get("tactics")),
                source=stage_source,
                events=(
                    _parse_events(raw.get("events"), source)
                    if stage_source in ("events", "any")
                    else EventConditions()
                ),
            )
        )
    if not stages:
        raise ValueError(f"[{source}] correlation rule needs at least one stage")

    group_by = str(data.get("group_by", "host")).lower()
    if group_by not in _GROUP_KEYS:
        raise ValueError(f"[{source}] group_by must be one of {_GROUP_KEYS}")
    match = str(data.get("match", "all")).lower()
    if match not in ("all", "any"):
        raise ValueError(f"[{source}] match must be 'all' or 'any'")
    severity = str(data.get("severity", "high")).lower()
    if severity not in _LEVELS:
        raise ValueError(f"[{source}] severity must be one of {_LEVELS}")

    spec = CorrelationSpec(
        name=str(data.get("name") or source),
        description=str(data.get("description", "")),
        enabled=bool(data.get("enabled", True)),
        severity=severity,
        confidence=max(0.0, min(1.0, float(data.get("confidence", 0.8)))),
        mitre_id=str(data.get("mitre_id", "T1071")),
        recommendation=str(data.get("recommendation", "")),
        window_minutes=max(1, int(data.get("window_minutes", 60))),
        group_by=group_by,
        match=match,
        stages=stages,
    )
    return spec


def load_correlation_rules(
    directory: str | Path | None = None,
) -> list[CorrelationSpec]:
    """Load and parse every YAML rule under ``directory``.

    Files with a ``.disabled`` suffix (``rule.yml.disabled``) are skipped so
    analysts can disable rules by renaming, like ``systemctl mask``.
    """
    import yaml

    directory = Path(directory or CORRELATION_RULES_DIR)
    if not directory.is_dir():
        return []
    specs: list[CorrelationSpec] = []
    for path in sorted(directory.glob("*.yml")) + sorted(directory.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            spec = parse_correlation_yaml(data, source=path.name)
            if spec.enabled:
                specs.append(spec)
                logger.info("Loaded correlation rule '%s' (%s)", spec.name, path.name)
            else:
                logger.info(
                    "Correlation rule '%s' disabled in %s", spec.name, path.name
                )
        except Exception as exc:
            logger.warning("Correlation rule %s skipped: %s", path.name, exc)
    return specs


class CorrelationEngine(BaseRule):
    """Config-driven correlation running the loaded YAML specs.

    Consumes both open alerts and raw events in the window, grouping each
    per entity (host / user / ip) so alert-stage and event-stage matches
    land on the same entity - a multi-source join in YAML form.
    """

    rule_id = "correlation_engine"
    name = "Declarative Multi-Stage Correlation"
    description = (
        "Evaluates YAML-defined correlation rules (window, group-by, ordered "
        "stages over alerts and raw events) for the same entity."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1071"
    recommendation = (
        "Correlate the contributing alerts/events as one incident; pivot on "
        "the entity in the entity graph and assume deeper compromise."
    )

    def __init__(self, session: Session, directory: str | Path | None = None):
        super().__init__(session)
        self.specs = load_correlation_rules(directory)

    def _group_alert(self, alert: Alert, group_by: str) -> str | None:
        """The entity key of an alert for the given grouping mode."""
        if group_by == "host":
            return (alert.host or "").strip() or None
        if group_by == "user":
            m = _USER_RE.search(alert.evidence or "")
            return m.group(1) if m else None
        if group_by == "ip":
            m = _EVENT_ID_RE.search(alert.evidence or "")
            return m.group(0) if m else None
        return "all"

    def _group_event(self, event: NormalizedEvent, group_by: str) -> str | None:
        """The entity key of a raw event; events carry no IP, so ip falls
        back to the host."""
        if group_by in ("host", "ip"):
            return (event.host or "").strip() or None
        if group_by == "user":
            return (event.user or "").strip() or None
        return "all"

    def evaluate(
        self, window_minutes: int, since_id: int | None = None
    ) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        if not self.specs:
            return findings
        since = datetime.now(UTC) - timedelta(minutes=window_minutes or 10)
        alerts = self.session.scalars(
            select(Alert).where(
                Alert.created_at >= since,
                Alert.status == "open",
                *self._org_conds(Alert),
            )
        ).all()
        events = self.session.scalars(
            select(NormalizedEvent).where(
                NormalizedEvent.timestamp >= since,
                *self._org_conds(NormalizedEvent),
            )
        ).all()

        for spec in self.specs:
            matched = self._evaluate_spec(spec, alerts, events)
            if matched:
                findings.append(matched)
        return findings

    def _evaluate_spec(
        self,
        spec: CorrelationSpec,
        alerts: list[Alert],
        events: list[NormalizedEvent],
    ) -> DetectionResult | None:
        # Per-entity, per-stage match sets from both sources. Every alert /
        # event is consumed by AT MOST ONE stage (the best match): the same
        # detection can never satisfy two independent stages, which would
        # inflate the chain's evidence with a single alert standing in for
        # two behaviours. A rule match beats a tactic-only match; ties go to
        # the earliest stage.
        by_group: dict[str, dict[int, list]] = {}
        for alert in alerts:
            if not spec.matches_any_alert(alert):
                continue
            key = self._group_alert(alert, spec.group_by)
            if key is None:
                continue
            chosen: tuple[int, bool] | None = None
            for idx, stage in enumerate(spec.stages):
                if not stage.matches_alert(alert):
                    continue
                rule_match = bool(stage.rules and alert.rule in stage.rules)
                if chosen is None or (rule_match and not chosen[1]):
                    chosen = (idx, rule_match)
            if chosen is not None:
                by_group.setdefault(key, {}).setdefault(chosen[0], []).append(alert)
        for event in events:
            if not spec.matches_any_event(event):
                continue
            key = self._group_event(event, spec.group_by)
            if key is None:
                continue
            chosen: tuple[int, bool] | None = None
            for idx, stage in enumerate(spec.stages):
                if not stage.matches_event(event):
                    continue
                if chosen is None or idx < chosen[0]:
                    chosen = (idx, True)
            if chosen is not None:
                by_group.setdefault(key, {}).setdefault(chosen[0], []).append(event)

        for key, stage_items in by_group.items():
            stage_ok = []
            for idx, stage in enumerate(spec.stages):
                items = stage_items.get(idx, [])
                if stage.source == "events":
                    if len(items) >= stage.events.min_count:
                        stage_ok.append((idx, items))
                elif items:
                    stage_ok.append((idx, items))
            matched_stages = [idx for idx, _ in stage_ok]
            if spec.match == "all" and len(matched_stages) < len(spec.stages):
                continue
            if spec.match == "any" and not matched_stages:
                continue
            evidence_lines = [
                (
                    f"Correlated {len(matched_stages)}/{len(spec.stages)} stages for '{key}' "
                    f"within {spec.window_minutes} min (match={spec.match}):"
                )
            ]
            for idx, items in stage_ok:
                stage = spec.stages[idx]
                if stage.source == "events":
                    sample = [e for e in items if isinstance(e, NormalizedEvent)]
                    evidence_lines.append(
                        f"  Stage '{stage.label}' (events): {len(sample)} event(s) "
                        f"[event_ids={sorted({e.event_id for e in sample[:20]})}] "
                        f"event_ids={[e.id for e in sample[:5]]}"
                    )
                else:
                    sample = [a for a in items if isinstance(a, Alert)]
                    evidence_lines.append(
                        f"  Stage '{stage.label}' (alerts): {len(sample)} alert(s) "
                        f"[{', '.join(sorted({a.rule for a in sample}))}] "
                        f"alert_ids={[a.id for a in sample[:5]]}"
                    )
            return DetectionResult(
                rule=self.rule_id,
                name=f"Correlated: {spec.name}",
                description=spec.description or self.description,
                severity=spec.severity,
                confidence=spec.confidence,
                evidence="\n".join(evidence_lines),
                event_ids=[],
                mitre_id=spec.mitre_id,
                recommendation=spec.recommendation or self.recommendation,
                correlation_id=self._next_correlation_id(),
            )
        return None

    def _next_correlation_id(self) -> str:
        """Deterministic per-day chain identifier: CORR-YYYYMMDD-NNNN.

        Shares the same numbering space as entity-risk notables so chain ids
        are globally unique and analysts can cross-reference them.
        """
        from sqlalchemy import func

        from backend.database.models import Alert

        day = datetime.now(UTC).strftime("%Y%m%d")
        prefix = f"CORR-{day}-"
        count = (
            self.session.scalar(
                select(func.count(Alert.id)).where(
                    Alert.correlation_id.like(f"{prefix}%")
                )
            )
            or 0
        )
        return f"{prefix}{count + 1:05d}"
