"""Investigation enrichment for incidents (Phase 1).

Aggregates everything the analyst needs from an incident's linked alerts
into one payload: evidence events, entity counts (files / processes /
network / registry), the who-what-when-where-how-why summary and the
process tree, so the incident page shows a full story instead of an
empty case folder.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime

from sqlalchemy import select

from backend.database.models import (
    AlertEventLink,
    Incident,
    IncidentAlertLink,
    NormalizedEvent,
)
from backend.investigation.process_tree import build_process_tree

log = logging.getLogger("investigation.enrichment")

ENRICHMENT_WINDOW_MINUTES = 30
MAX_EVENTS = 300


def _fact(ev: NormalizedEvent, *keys: str) -> str:
    facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
    for key in keys:
        for k, v in facts.items():
            if k.lower() == key.lower():
                return str(v)
    return ""


def _is_network_event(ev: NormalizedEvent) -> bool:
    return ev.event_id in (3, 5156, 5157) or ev.category == "network"


def _is_registry_event(ev: NormalizedEvent) -> bool:
    return ev.event_id in (12, 13, 14, 4657) or (
        ev.category == "registry" and "registry" in (ev.message or "").lower()
    )


def incident_events(session, incident: Incident) -> list[NormalizedEvent]:
    """All events linked to the incident through its alerts (de-duplicated)."""
    ids = set(session.scalars(
        select(AlertEventLink.event_id)
        .join(IncidentAlertLink, IncidentAlertLink.alert_id == AlertEventLink.alert_id)
        .where(IncidentAlertLink.incident_id == incident.id)
    ).all())
    if not ids:
        return []
    return session.scalars(
        select(NormalizedEvent).where(NormalizedEvent.id.in_(list(ids))).limit(MAX_EVENTS)
    ).all()


def _file_names(events: list[NormalizedEvent]) -> list[str]:
    names = set()
    for ev in events:
        for key in ("target_filename", "file_path", "image_path", "new_process", "NewProcessName", "Image"):
            val = _fact(ev, key)
            if val:
                names.add(val.rsplit("\\", 1)[-1])
                break
    return sorted(names)


def _process_names(events: list[NormalizedEvent]) -> list[str]:
    names = set()
    for ev in events:
        for key in ("new_process", "NewProcessName", "Image", "image_path", "process_name"):
            val = _fact(ev, key)
            if val:
                names.add(val.rsplit("\\", 1)[-1])
                break
    return sorted(names)


def _network_events(events: list[NormalizedEvent]) -> list[dict]:
    """Network telemetry from the incident's own evidence events only.

    Dedicated NetworkConnection rows are deliberately NOT included: they
    are not linked to alerts/incidents, so pulling them by time window
    would surface unrelated traffic and inflate the enrichment.
    """
    out: list[dict] = []
    seen: set[int] = set()
    for ev in events:
        if not _is_network_event(ev) or ev.id in seen:
            continue
        seen.add(ev.id)
        out.append({
            "event_id": ev.id,
            "ts": ev.timestamp.isoformat() if ev.timestamp else None,
            "remote_ip": _fact(ev, "remote_ip", "dest_ip", "destination_ip"),
            "local_ip": _fact(ev, "local_ip", "source_ip"),
            "message": (ev.message or "")[:160],
        })
    return out[:50]


def _registry_events(events: list[NormalizedEvent]) -> list[dict]:
    out = []
    for ev in events:
        if not _is_registry_event(ev):
            continue
        out.append({
            "event_id": ev.id,
            "ts": ev.timestamp.isoformat() if ev.timestamp else None,
            "target": _fact(ev, "target_object", "object"),
            "message": (ev.message or "")[:160],
        })
    return out[:50]


def _six_w(session, incident: Incident, events: list[NormalizedEvent]) -> dict:
    """Who / What / When / Where / How / Why answers from the evidence."""
    users = sorted({ev.user for ev in events if ev.user and ev.user not in ("-", "")})
    hosts = sorted({ev.host for ev in events if ev.host and ev.host not in ("-", "")})
    timestamps = [ev.timestamp for ev in events if ev.timestamp]
    categories = Counter(
        "process" if ev.event_id == 4688 else
        "network" if _is_network_event(ev) else
        "registry" if _is_registry_event(ev) else
        "auth" if ev.event_id in (4624, 4625, 4672) else
        "script" if ev.event_id in (4103, 4104) else
        "persistence" if ev.event_id in (7045, 4698) else
        "other"
        for ev in events
    )

    mitre_steps = {
        4625: "Credential probing",
        4624: "Access granted",
        4720: "Account creation",
        4732: "Privilege assignment",
        4672: "Privileged logon",
        4104: "Script execution",
        7045: "Persistence installed",
        4698: "Scheduled persistence",
        4688: "Process created",
    }
    steps = []
    seen: set[int] = set()
    for ev in sorted(events, key=lambda e: e.timestamp or datetime.min):
        if ev.event_id in seen:
            continue
        step = mitre_steps.get(ev.event_id)
        if step:
            seen.add(ev.event_id)
            steps.append(step)
    if not steps:
        steps = ["Observation"]

    return {
        "who": users[:10],
        "what": _process_names(events)[:10],
        "when": {
            "first": min(timestamps).isoformat() if timestamps else None,
            "last": max(timestamps).isoformat() if timestamps else None,
            "span_seconds": round((max(timestamps) - min(timestamps)).total_seconds(), 1) if len(timestamps) > 1 else 0,
        },
        "where": hosts[:10],
        "how": steps[:10],
        "why": {
            "mitre_id": incident.mitre_id,
            "mitre_name": incident.mitre_name,
            "categories": dict(categories.most_common(6)),
        },
    }


def enrich_incident(session, incident: Incident, window_minutes: int = ENRICHMENT_WINDOW_MINUTES) -> dict:
    """Full investigation payload for an incident."""
    events = incident_events(session, incident)
    tree = build_process_tree(session, events, org=incident.org or "", window_minutes=window_minutes)

    evidence = []
    for alert in sorted({l.alert for l in incident.alerts if l.alert}, key=lambda a: a.id):
        evidence.append({
            "alert_id": alert.id,
            "name": alert.name,
            "severity": alert.severity,
            "confidence": alert.confidence,
            "mitre_id": alert.mitre_id,
            "evidence": (alert.evidence or "")[:600],
        })

    files = _file_names(events)
    processes = _process_names(events)
    network = _network_events(events)
    registry = _registry_events(events)

    # Roadmap P2 (feature 7) - root cause engine: automatic summary,
    # observations and assessment, with the dynamic-risk view behind it.
    from backend.context import assess_events
    from backend.investigation.root_cause import root_cause
    from backend.risk.dynamic import adjust_risk

    base_risk = float(incident.risk_score or 0) or max(
        (float(a.risk_score or 0) for a in incident.alerts
         if a.alert and a.alert.risk_score),
        default=0.0,
    )
    facts = assess_events(events, rule="")
    risk = adjust_risk(base_risk, facts, events, session=session)
    rc = root_cause(
        session, incident=incident, events=events,
        facts=facts, risk=risk, tree=tree,
    )

    return {
        "event_count": len(events),
        "related_alerts": len(incident.alerts),
        "files": files,
        "file_count": len(files),
        "processes": processes,
        "process_count": len(processes),
        "network_events": network,
        "network_count": len(network),
        "registry_events": registry,
        "registry_count": len(registry),
        "evidence": evidence,
        "process_tree": tree,
        "six_w": _six_w(session, incident, events),
        "root_cause": rc,
    }