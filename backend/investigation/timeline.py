"""Timeline correlation for the investigation view.

Builds one merged, time-ordered story: the alert's evidence events, the
process-creation events from the reconstructed tree, host/user-scoped
surrounding events (instead of a whole-tenant time window), network
connections and related-alert markers.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from backend.database.models import Alert, AlertEventLink, NetworkConnection, NormalizedEvent

TIMELINE_WINDOW_MINUTES = 30
MAX_EVENTS = 300


def build_timeline(
    session,
    alert: Alert,
    evidence_events: list[NormalizedEvent],
    tree: dict,
) -> list[dict]:
    """Merged, chronological story timeline around the alert."""
    entries: list[dict] = []

    timestamps = [ev.timestamp for ev in evidence_events if ev.timestamp]
    if not timestamps:
        return entries
    ts_min = min(timestamps) - timedelta(minutes=TIMELINE_WINDOW_MINUTES)
    ts_max = max(timestamps) + timedelta(minutes=TIMELINE_WINDOW_MINUTES)

    hosts = {ev.host for ev in evidence_events if ev.host}
    users = {ev.user for ev in evidence_events if ev.user}

    # evidence events first (they define the story)
    for ev in evidence_events:
        entries.append({
            "kind": "event",
            "tag": "evidence",
            "ref": ev.id,
            "ts": ev.timestamp.isoformat(),
            "title": ev.message[:160],
            "detail": f"{ev.category} {ev.event_id} user={ev.user} host={ev.host}",
            "severity": ev.severity,
            "risk_score": ev.risk_score,
        })

    # process-tree events (4688s in the window)
    tree_ts_min = ts_min - timedelta(minutes=45)
    tree_ts_max = ts_max + timedelta(minutes=45)
    q = select(NormalizedEvent).where(
        NormalizedEvent.event_id == 4688,
        NormalizedEvent.timestamp >= tree_ts_min,
        NormalizedEvent.timestamp <= tree_ts_max,
    )
    if alert.org:
        q = q.where(NormalizedEvent.org == alert.org)
    else:
        q = q.where(NormalizedEvent.demo == False)  # noqa: E712
    q = q.order_by(NormalizedEvent.timestamp.asc()).limit(200)
    for ev in session.scalars(q).all():
        entries.append({
            "kind": "event",
            "tag": "process",
            "ref": ev.id,
            "ts": ev.timestamp.isoformat(),
            "title": f"Process created: {ev.message[:140]}",
            "detail": f"user={ev.user} host={ev.host}",
            "severity": ev.severity,
            "risk_score": ev.risk_score,
        })

    # host/user-scoped surrounding events (replaces whole-tenant ±30min)
    q2 = select(NormalizedEvent).where(
        NormalizedEvent.timestamp >= ts_min,
        NormalizedEvent.timestamp <= ts_max,
    )
    if hosts:
        q2 = q2.where(NormalizedEvent.host.in_(list(hosts)))
    if users:
        q2 = q2.where(NormalizedEvent.user.in_(list(users)))
    if not hosts and not users:
        q2 = q2.where(NormalizedEvent.id.in_(
            select(AlertEventLink.event_id).where(AlertEventLink.alert_id == alert.id)
        ))
    if alert.org:
        q2 = q2.where(NormalizedEvent.org == alert.org)
    else:
        q2 = q2.where(NormalizedEvent.demo == False)  # noqa: E712
    q2 = q2.order_by(NormalizedEvent.timestamp.asc()).limit(MAX_EVENTS)
    for ev in session.scalars(q2).all():
        entries.append({
            "kind": "event",
            "tag": "context",
            "ref": ev.id,
            "ts": ev.timestamp.isoformat(),
            "title": ev.message[:160],
            "detail": f"{ev.category} {ev.event_id} user={ev.user} host={ev.host}",
            "severity": ev.severity,
            "risk_score": ev.risk_score,
        })

    # network connections in the window
    try:
        q3 = select(NetworkConnection).where(
            NetworkConnection.observed_at >= ts_min,
            NetworkConnection.observed_at <= ts_max,
        )
        if alert.org:
            q3 = q3.where(NetworkConnection.org == alert.org)
        else:
            q3 = q3.where(NetworkConnection.demo == False)  # noqa: E712
        q3 = q3.order_by(NetworkConnection.observed_at.asc()).limit(50)
        for conn in session.scalars(q3).all():
            entries.append({
                "kind": "network",
                "tag": "network",
                "ref": conn.id,
                "ts": conn.observed_at.isoformat(),
                "title": f"{conn.process or f'pid {conn.pid}'} -> {conn.remote_ip}:{conn.remote_port} ({conn.state})",
                "detail": f"{conn.local_ip}:{conn.local_port} remote={conn.remote_ip}:{conn.remote_port}",
                "severity": "info",
                "risk_score": None,
            })
    except Exception:  # noqa: BLE001
        pass

    # related-alert markers (from the cluster)
    for cand in tree.get("_related_alerts") or []:
        if cand.get("id") == alert.id:
            continue
        entries.append({
            "kind": "alert",
            "tag": "related",
            "ref": cand["id"],
            "ts": cand["created_at"],
            "title": f"Related alert: {cand['name']}",
            "detail": f"{cand['rule']} severity={cand['severity']}",
            "severity": cand["severity"],
            "risk_score": cand.get("risk_score"),
        })

    entries.sort(key=lambda e: e["ts"])
    return entries