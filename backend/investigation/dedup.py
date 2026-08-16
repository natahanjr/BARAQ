"""Incident deduplication engine (Phase 1).

New alerts are folded into an existing *open* incident instead of spawning
a duplicate when they share the same correlation key - ``user | host |
mitre technique | root process | 30-minute window`` - so a campaign that
fires N alerts produces one incident with N linked alerts, not N
near-identical incidents.

The key is stored on the incident row so the merge is a single indexed
lookup; root process is derived from the evidence's 4688 process chain.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from backend.database.models import Alert, Incident, IncidentAlertLink, NormalizedEvent

log = logging.getLogger("investigation.dedup")

#: Dedup window: alerts within this many minutes of an open incident's
#: creation with the same key are absorbed into it.
DEDUP_WINDOW_MINUTES = 30
#: Bucket size used to quantize the window (aligns alerts that land a few
#: minutes apart in the same bucket).
WINDOW_BUCKET_MINUTES = 30
#: Incident statuses that stay open for merge purposes.
ACTIVE_STATES = ("open", "investigating", "contained")

PROCESS_CREATE_EVENT = 4688


def _evidence_user(alert: Alert) -> str:
    """Best-effort user extraction from evidence text + linked events."""
    text = alert.evidence or ""
    m = re.search(r"\b(?:user|account|subject user name)\s*[':=]\s*([^\s',]+)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    for link in list(alert.events)[:8]:
        if link.event and link.event.user:
            return link.event.user
    return ""


def _root_process(session, alert: Alert, window_minutes: int = 90) -> str:
    """Root process name of the evidence chain, or "" when unavailable.

    Walks the 4688 facts (``NewProcessId``/``ProcessId`` parent links)
    from the evidence PIDs up to the oldest ancestor in the window.
    """
    try:
        pids = []
        for link in list(alert.events)[:50]:
            facts = (link.event.raw_json or {}).get("facts", {}) if link.event and link.event.raw_json else {}
            pid = None
            for key in ("NewProcessId", "ProcessId", "pid"):
                for k, v in facts.items():
                    if k.lower() == key.lower():
                        pid = v
                        break
                if pid:
                    break
            if pid:
                pids.append(str(pid).strip())
        if not pids:
            return ""

        timestamps = [l.event.timestamp for l in alert.events if l.event and l.event.timestamp]
        if not timestamps:
            return ""
        ts_min = min(timestamps) - timedelta(minutes=window_minutes)
        ts_max = max(timestamps) + timedelta(minutes=window_minutes)
        q = select(NormalizedEvent).where(
            NormalizedEvent.event_id == PROCESS_CREATE_EVENT,
            NormalizedEvent.timestamp >= ts_min,
            NormalizedEvent.timestamp <= ts_max,
        )
        # Process trees are per-host: never let same-PID processes on other
        # hosts masquerade as this alert's ancestry.
        if alert.host:
            q = q.where(NormalizedEvent.host == alert.host)
        if alert.org:
            q = q.where(NormalizedEvent.org == alert.org)
        else:
            q = q.where(NormalizedEvent.demo.is_(False))
        q = q.order_by(NormalizedEvent.timestamp.asc()).limit(2000)

        parent_of: dict[str, str] = {}
        name_of: dict[str, str] = {}
        for ev in session.scalars(q).all():
            facts = (ev.raw_json or {}).get("facts", {}) if ev.raw_json else {}
            child = parent = name = None
            for key in ("NewProcessId", "ProcessId", "pid"):
                for k, v in facts.items():
                    if k.lower() == key.lower():
                        child = str(v).strip()
                        break
                if child:
                    break
            if not child:
                continue
            for key in ("ProcessId", "ParentProcessId", "ParentPID", "ppid"):
                for k, v in facts.items():
                    if k.lower() == key.lower():
                        parent = str(v).strip()
                        break
                if parent:
                    break
            for key in ("new_process", "NewProcessName", "Image"):
                for k, v in facts.items():
                    if k.lower() == key.lower():
                        name = str(v).rsplit("\\", 1)[-1]
                        break
                if name:
                    break
            if parent:
                parent_of[child] = parent
            if name:
                name_of[child] = name

        # Walk up from every evidence pid; report the oldest named ancestor.
        # A chain-top event may still carry ParentProcessId "0", so when the
        # walk exhausts without a name we fall back to the deepest named
        # ancestor seen (e.g. cmd.exe under pid 0) instead of reporting "".
        root_name = ""
        for pid in pids:
            cur = pid
            best = ""
            seen: set[str] = set()
            while cur and cur not in seen and cur in parent_of:
                seen.add(cur)
                if cur in name_of:
                    best = name_of[cur]
                cur = parent_of[cur]
            if cur and cur in name_of:
                root_name = name_of[cur]
            elif best:
                root_name = best
        return root_name
    except Exception:  # noqa: BLE001 - dedup must never break alerting
        log.debug("root process derivation failed for alert %s", alert.id, exc_info=True)
        return ""


def correlation_key(session, alert: Alert, now: datetime | None = None) -> str:
    """Compute the dedup key for an alert."""
    now = now or datetime.now(timezone.utc)
    bucket = int(now.timestamp() // (WINDOW_BUCKET_MINUTES * 60))
    user = _evidence_user(alert) or "?"
    host = alert.host or "?"
    mitre = alert.mitre_id or "T0000"
    root = _root_process(session, alert) or ""
    return f"{user}|{host}|{mitre}|{root}|{bucket}"


def find_open_incident(session, key: str, org: str = "") -> Incident | None:
    """Open incident with the same correlation key (indexed lookup)."""
    if not key:
        return None
    q = select(Incident).where(
        Incident.correlation_key == key,
        Incident.status.in_(ACTIVE_STATES),
    )
    if org:
        q = q.where(Incident.org == org)
    return session.scalars(q.order_by(Incident.created_at.asc()).limit(1)).first()


def merge_alert(session, incident: Incident, alert: Alert) -> bool:
    """Fold an alert into an open incident; returns True when newly linked."""
    existing = {
        l.alert_id for l in incident.alerts
    }
    if alert.id in existing:
        incident.updated_at = datetime.now(timezone.utc)
        return False
    session.add(IncidentAlertLink(incident_id=incident.id, alert_id=alert.id))
    incident.updated_at = datetime.now(timezone.utc)
    incident.risk_score = min(100.0, max(incident.risk_score or 0.0, alert.risk_score or 0.0))
    if _severity_rank(alert.severity) > _severity_rank(incident.severity):
        incident.severity = alert.severity
    if not incident.host and alert.host:
        incident.host = alert.host
    if not incident.mitre_id or incident.mitre_id == "T0000":
        incident.mitre_id = alert.mitre_id
        incident.mitre_name = alert.mitre_name

    # Re-score story confidence after the merge: more corroborating alerts
    # raise detection quality, so confidence can only improve or stay flat.
    try:
        session.flush()
        session.expire(incident)
        from backend.investigation.confidence import incident_confidence

        incident.confidence = incident_confidence(session, incident)["score"]
    except Exception:  # noqa: BLE001 - confidence must never break merging
        log.debug("confidence recompute failed for incident %s", incident.id, exc_info=True)
    return True


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(severity).lower(), 2)