"""Attack-chain reconstruction for incidents (P1-1).

Rebuilds the multi-stage attack path (Discovery -> Execution -> Collection
-> Exfiltration, per ``KILL_CHAIN_STAGES``) of an incident from its linked
alerts, and derives two numbers the analyst can act on:

* **chain confidence** (0..1) - how much this stage sequence looks like a
  coordinated campaign: stage count, canonical ordering, a terminal stage
  (exfiltration / lateral movement) and ancestry cohesion (all alerts
  sharing one root process).
* **chain risk** (+0..20) - the deterministic risk boost applied on top of
  the strongest contributing alert's risk, so a *sequence* of detections
  scores higher than any single detection alone.

The chain is persisted on the incident (``chain_json``) and refreshed every
time an alert is absorbed into the incident, so the case narrative grows as
the campaign unfolds.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from sqlalchemy import select

from backend.database.models import Alert, Incident, IncidentAlertLink

#: Parse fallback: a correlation finding names its stages in evidence as
#: "(Initial Access, Execution, ...)" - sorted longest-first so multi-word
#: stages like "Exfiltration / C2" match before their prefixes.
_STAGE_NAMES = sorted(
    {
        "Initial Access",
        "Initial Access / Tool Transfer",
        "Credential Access",
        "Execution",
        "Privilege Escalation",
        "Persistence",
        "Collection",
        "Exfiltration / C2",
        "Lateral Movement",
        "Discovery",
        "Defense Evasion",
        "Other",
    },
    key=len,
    reverse=True,
)

_CONF_BASE = 0.35
_CONF_PER_STAGE = 0.15
_CONF_ORDERED = 0.10
_CONF_TERMINAL = 0.10
_CONF_COHESIVE_ROOT = 0.10
_CONF_CAP = 0.95

_RISK_PER_STAGE = 5
_RISK_ORDERED = 5
_RISK_TERMINAL = 5
_RISK_COHESIVE_ROOT = 5
_RISK_CAP = 20


def _linked_alerts(db, incident: Incident) -> list[Alert]:
    return list(
        db.scalars(
            select(Alert)
            .join(IncidentAlertLink, IncidentAlertLink.alert_id == Alert.id)
            .where(IncidentAlertLink.incident_id == incident.id)
        ).all()
    )


def _stage_timeline(stages: dict[str, datetime]) -> tuple[list[str], float, float, float]:
    """(ordered stage names, span minutes, max inter-stage gap, ordered ratio).

    Reuses the same ordering math as the kill-chain correlation rule so
    incident chains and correlation findings never disagree.
    """
    from backend.detection.rules.correlation import KILL_CHAIN_STAGES

    order_index = {name: i for i, name in enumerate(KILL_CHAIN_STAGES.values())}
    timed = [(ts, name) for name, ts in stages.items() if ts is not None]
    timed.sort(key=lambda pair: pair[0])
    sequence = [name for _, name in timed]
    untimed = [name for name in stages if name not in sequence]
    sequence.extend(untimed)

    if len(timed) < 2:
        return sequence, 0.0, 0.0, 1.0 if len(sequence) <= 1 else 0.0

    first, last = timed[0][0], timed[-1][0]
    span_min = (last - first).total_seconds() / 60.0
    max_gap = max((t2 - t1).total_seconds() / 60.0 for (t1, _), (t2, _) in zip(timed, timed[1:]))

    strict = [s for s in sequence if s != "Discovery"]
    index_seq = [order_index.get(s, 9999) for s in strict]
    ordered = sum(1 for a, b in zip(index_seq, index_seq[1:]) if b > a)
    ratio = ordered / max(len(index_seq) - 1, 1)
    return sequence, float(span_min), float(max_gap), float(ratio)


_STAGE_ALTERNATION = "|".join(re.escape(n) for n in sorted(_STAGE_NAMES, key=len, reverse=True))


def _evidence_stage_fallback(evidence: str) -> list[str]:
    """Parse "(Initial Access, Execution, ...)" stage list from evidence.

    Returns stages in the OBSERVED (text) order - the correlation finding
    names them in the sequence they fired, which is what the analyst sees.
    """
    if not evidence:
        return []
    for m in re.finditer(r"\(([^()]*)\)", evidence):
        inner = m.group(1)
        found = [name for name in re.findall(_STAGE_ALTERNATION, inner) if name != "Other"]
        if len(found) >= 2:
            return found
    return []


def reconstruct_chain(db, incident: Incident) -> dict:
    """Rebuild the attack chain of an incident; empty chain when <2 stages."""
    from backend.investigation.dedup import _evidence_user, _root_process

    alerts = _linked_alerts(db, incident)
    if not alerts:
        return _empty_chain()

    from backend.detection.rules.correlation import KILL_CHAIN_STAGES

    stage_first: dict[str, datetime] = {}
    for alert in alerts:
        stage = KILL_CHAIN_STAGES.get(alert.rule, "Other")
        created = alert.created_at
        if stage_first.get(stage) is None or (created and created < stage_first[stage]):
            stage_first[stage] = created

    fallback = _evidence_stage_fallback(alert.evidence or "")
    for name in fallback:
        stage_first.setdefault(name, alert.created_at)

    stage_first.pop("Other", None)
    if len(stage_first) < 2:
        return _empty_chain()

    sequence, span_min, max_gap_min, ordered_ratio = _stage_timeline(stage_first)
    ordered = ordered_ratio == 1.0 and len(sequence) > 1
    has_terminal = bool(set(stage_first) & {"Exfiltration / C2", "Lateral Movement"})

    roots = {_root_process(db, a) for a in alerts}
    roots.discard("")
    hosts = {a.host or "" for a in alerts}
    hosts.discard("")
    # Ancestry cohesion requires ONE host AND one root process - identical
    # process names on two different machines are two separate campaigns.
    cohesive_root = len(hosts) == 1 and len(roots) == 1

    stages = [
        {
            "name": name,
            "first_seen": stage_first[name].isoformat() if stage_first[name] else None,
        }
        for name in sequence
    ]

    confidence = min(
        _CONF_CAP,
        _CONF_BASE
        + len(sequence) * _CONF_PER_STAGE
        + (_CONF_ORDERED if ordered else 0.0)
        + (_CONF_TERMINAL if has_terminal else 0.0)
        + (_CONF_COHESIVE_ROOT if cohesive_root else 0.0),
    )

    risk_boost = min(
        _RISK_CAP,
        _RISK_PER_STAGE * max(len(sequence) - 1, 1)
        + (_RISK_ORDERED if ordered else 0)
        + (_RISK_TERMINAL if has_terminal else 0)
        + (_RISK_COHESIVE_ROOT if cohesive_root else 0),
    )

    narrative_parts = [f"{len(sequence)}-stage attack chain on {incident.host or 'unknown host'}"]
    if ordered:
        narrative_parts.append("stages follow the canonical kill-chain order")
    if has_terminal:
        narrative_parts.append("terminal stage reached (exfiltration / lateral movement)")
    if cohesive_root:
        narrative_parts.append("alerts share a single root process")
    narrative_parts.append(f"chain span {span_min:.0f} min" if span_min else "timing unavailable")

    return {
        "stages": stages,
        "sequence": sequence,
        "span_min": round(span_min, 1),
        "max_gap_min": round(max_gap_min, 1),
        "ordered": ordered,
        "ordered_ratio": round(ordered_ratio, 2),
        "has_terminal": has_terminal,
        "cohesive_root": cohesive_root,
        "root_process": next(iter(roots), ""),
        "confidence": round(confidence, 2),
        "risk_boost": risk_boost,
        "narrative": "; ".join(narrative_parts),
        "alert_count": len(alerts),
    }


def _empty_chain() -> dict:
    return {
        "stages": [],
        "sequence": [],
        "span_min": 0.0,
        "max_gap_min": 0.0,
        "ordered": False,
        "ordered_ratio": 0.0,
        "has_terminal": False,
        "cohesive_root": False,
        "root_process": "",
        "confidence": 0.0,
        "risk_boost": 0,
        "narrative": "Not enough stages to reconstruct an attack chain",
        "alert_count": 0,
    }


def apply_chain(db, incident: Incident) -> dict:
    """Recompute + persist the chain, then re-apply chain risk.

    Risk model: the strongest contributing alert's risk sets the base;
    the chain boost stacks on top (capped at 100). This is deterministic -
    the same alert set always yields the same risk.
    """
    chain = reconstruct_chain(db, incident)
    if chain["sequence"]:
        incident.chain_json = json.dumps(chain, default=str)
        incident.chain_confidence = chain["confidence"]
        incident.chain_risk = chain["risk_boost"]
    else:
        incident.chain_json = None
        incident.chain_confidence = 0.0
        incident.chain_risk = 0

    base = 0.0
    for alert in _linked_alerts(db, incident):
        base = max(base, alert.risk_score or 0.0)
    new_risk = min(100.0, base + incident.chain_risk)
    if abs(new_risk - (incident.risk_score or 0.0)) >= 0.01:
        incident.risk_score = round(new_risk, 2)
        try:
            from backend.risk.dynamic import roadmap_level

            incident.risk_level = roadmap_level(new_risk)
        except Exception:  # noqa: BLE001 - risk label is cosmetic
            pass
    db.flush()
    return chain