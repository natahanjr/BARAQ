"""Entity extraction - turn raw telemetry into graph nodes & edges.

Two entry points, both provider-agnostic (they talk to :class:`GraphStore`):

* :func:`sync_graph` - full aggregate rebuild from the events/alerts/
  telemetry tables. Called on demand (``POST /api/entities/sync``) and at
  startup when the graph is empty.
* :func:`ingest_batch` - cheap, targeted upserts for the records + alerts a
  single pipeline run just persisted (keeps the graph fresh in real time
  without a full scan on every ingest).

Relationship vocabulary (labels used by the UI):
``LOGON_ON`` (user->device), ``RUNS_AS`` (process->user), ``CONNECTS_TO``
(process->ip), ``QUERIES`` (process->domain), ``RESOLVES_TO``
(domain->ip), ``REQUESTS`` (process->domain), ``EXHIBITS`` (user/device->
technique).
"""
from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import func, select

from backend.database.models import (
    AlertEventLink,
    Alert,
    DnsQuery,
    EntityEdge,
    EntityNode,
    FileScan,
    HttpRequest,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
    ThreatIntelRecord,
)
from backend.graph.base import GraphStore

logger = logging.getLogger("baraq.graph")

RISK_INTEL_BOOST = {"malicious": 0.95, "suspicious": 0.7, "abusive": 0.5}


def _risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _node(kind: str, name: str, risk: float = 0.0, label: str = "",
          alerts: int = 0, events: int = 1, props: dict | None = None,
          first=None, last=None) -> dict:
    return {
        "kind": kind, "name": name, "display_name": label or name, "label": label,
        "risk_level": _risk_level(risk), "risk_score": round(risk, 2),
        "alerts_count": alerts, "events_count": events,
        "properties": props or {}, "first_seen": first, "last_seen": last,
    }


def _edge(src_kind, src_name, rel, dst_kind, dst_name, weight=1,
          first=None, last=None, props: dict | None = None) -> dict:
    return {
        "src_kind": src_kind, "src_name": src_name, "rel": rel,
        "dst_kind": dst_kind, "dst_name": dst_name, "weight": weight,
        "first_seen": first, "last_seen": last, "properties": props or {},
    }


def _intel_risk(db, indicator: str) -> float:
    rec = db.scalar(
        select(ThreatIntelRecord).where(ThreatIntelRecord.indicator == indicator)
    )
    if rec and rec.category in RISK_INTEL_BOOST:
        return RISK_INTEL_BOOST[rec.category] * 100.0
    return 0.0


def sync_graph(db, store: GraphStore) -> dict:
    """Full aggregate rebuild: events/telemetry tables -> nodes + edges."""
    if store.name == "neo4j":
        # Neo4j backend keeps its own ingestion; skip the SQL scan.
        return {"provider": store.name, "skipped": True}

    nodes: list[dict] = []
    edges: list[dict] = []

    # --- users (events) ---------------------------------------------------
    rows = db.execute(
        select(
            NormalizedEvent.user,
            func.count().label("c"),
            func.max(NormalizedEvent.risk_score).label("mx"),
            func.min(NormalizedEvent.timestamp).label("mn"),
            func.max(NormalizedEvent.timestamp).label("mx_ts"),
        )
        .where(NormalizedEvent.user.isnot(None), NormalizedEvent.user != "-")
        .group_by(NormalizedEvent.user)
    ).all()
    for r in rows:
        risk = max(r.mx or 0, 0)
        nodes.append(_node(
            "user", r.user, risk, label=f"User: {r.user}", events=r.c,
            props={"account": r.user}, first=r.mn, last=r.mx_ts,
        ))

    # --- devices (events.host) -------------------------------------------
    rows = db.execute(
        select(
            NormalizedEvent.host,
            func.count().label("c"),
            func.max(NormalizedEvent.risk_score).label("mx"),
            func.min(NormalizedEvent.timestamp).label("mn"),
            func.max(NormalizedEvent.timestamp).label("mx_ts"),
        )
        .where(NormalizedEvent.host.isnot(None), NormalizedEvent.host != "-")
        .group_by(NormalizedEvent.host)
    ).all()
    for r in rows:
        nodes.append(_node(
            "device", r.host, max(r.mx or 0, 0), label=f"Device: {r.host}",
            events=r.c, props={"hostname": r.host}, first=r.mn, last=r.mx_ts,
        ))

    # --- user -> device (LOGON_ON) ---------------------------------------
    rows = db.execute(
        select(
            NormalizedEvent.user, NormalizedEvent.host, func.count().label("c"),
            func.min(NormalizedEvent.timestamp).label("mn"),
            func.max(NormalizedEvent.timestamp).label("mx_ts"),
        )
        .where(
            NormalizedEvent.user.isnot(None), NormalizedEvent.user != "-",
            NormalizedEvent.host.isnot(None), NormalizedEvent.host != "-",
        )
        .group_by(NormalizedEvent.user, NormalizedEvent.host)
    ).all()
    for r in rows:
        edges.append(_edge(
            "user", r.user, "LOGON_ON", "device", r.host, weight=r.c,
            first=r.mn, last=r.mx_ts,
        ))

    # --- processes --------------------------------------------------------
    rows = db.execute(
        select(
            ProcessRecord.name, func.count().label("c"),
            func.min(ProcessRecord.observed_at).label("mn"),
            func.max(ProcessRecord.observed_at).label("mx_ts"),
        )
        .where(ProcessRecord.name.isnot(None), ProcessRecord.name != "")
        .group_by(ProcessRecord.name)
    ).all()
    for r in rows:
        nodes.append(_node(
            "process", r.name, 0.0, label=f"Process: {r.name}", events=r.c,
            props={"process_name": r.name}, first=r.mn, last=r.mx_ts,
        ))

    # --- process -> user (RUNS_AS) ----------------------------------------
    rows = db.execute(
        select(
            ProcessRecord.name, ProcessRecord.user, func.count().label("c"),
            func.min(ProcessRecord.observed_at).label("mn"),
            func.max(ProcessRecord.observed_at).label("mx_ts"),
        )
        .where(
            ProcessRecord.name.isnot(None), ProcessRecord.name != "",
            ProcessRecord.user.isnot(None), ProcessRecord.user != "",
        )
        .group_by(ProcessRecord.name, ProcessRecord.user)
    ).all()
    for r in rows:
        edges.append(_edge(
            "process", r.name, "RUNS_AS", "user", r.user, weight=r.c,
            first=r.mn, last=r.mx_ts,
        ))

    # --- ip addresses (network) -------------------------------------------
    rows = db.execute(
        select(
            NetworkConnection.remote_ip, func.count().label("c"),
            func.min(NetworkConnection.observed_at).label("mn"),
            func.max(NetworkConnection.observed_at).label("mx_ts"),
        )
        .where(NetworkConnection.remote_ip.isnot(None), NetworkConnection.remote_ip != "")
        .group_by(NetworkConnection.remote_ip)
    ).all()
    for r in rows:
        risk = _intel_risk(db, r.remote_ip)
        nodes.append(_node(
            "ip", r.remote_ip, risk, label=f"IP: {r.remote_ip}", events=r.c,
            props={"ip": r.remote_ip}, first=r.mn, last=r.mx_ts,
        ))

    # --- process -> ip (CONNECTS_TO) --------------------------------------
    rows = db.execute(
        select(
            NetworkConnection.process, NetworkConnection.remote_ip,
            func.count().label("c"),
            func.min(NetworkConnection.observed_at).label("mn"),
            func.max(NetworkConnection.observed_at).label("mx_ts"),
        )
        .where(
            NetworkConnection.process.isnot(None), NetworkConnection.process != "",
            NetworkConnection.remote_ip.isnot(None), NetworkConnection.remote_ip != "",
        )
        .group_by(NetworkConnection.process, NetworkConnection.remote_ip)
    ).all()
    for r in rows:
        edges.append(_edge(
            "process", r.process, "CONNECTS_TO", "ip", r.remote_ip, weight=r.c,
            first=r.mn, last=r.mx_ts,
        ))

    # --- domains (dns) ----------------------------------------------------
    rows = db.execute(
        select(
            DnsQuery.query, func.count().label("c"),
            func.min(DnsQuery.observed_at).label("mn"),
            func.max(DnsQuery.observed_at).label("mx_ts"),
        )
        .where(DnsQuery.query.isnot(None), DnsQuery.query != "")
        .group_by(DnsQuery.query)
    ).all()
    for r in rows:
        risk = _intel_risk(db, r.query)
        nodes.append(_node(
            "domain", r.query, risk, label=f"Domain: {r.query}", events=r.c,
            props={"domain": r.query}, first=r.mn, last=r.mx_ts,
        ))

    # --- process -> domain (QUERIES) + domain -> ip (RESOLVES_TO) ---------
    rows = db.execute(
        select(
            DnsQuery.process, DnsQuery.query, func.count().label("c"),
            func.min(DnsQuery.observed_at).label("mn"),
            func.max(DnsQuery.observed_at).label("mx_ts"),
        )
        .where(DnsQuery.process.isnot(None), DnsQuery.process != "")
        .group_by(DnsQuery.process, DnsQuery.query)
    ).all()
    for r in rows:
        edges.append(_edge(
            "process", r.process, "QUERIES", "domain", r.query, weight=r.c,
            first=r.mn, last=r.mx_ts,
        ))
    rows = db.execute(
        select(
            DnsQuery.query, DnsQuery.response, func.count().label("c"),
            func.min(DnsQuery.observed_at).label("mn"),
            func.max(DnsQuery.observed_at).label("mx_ts"),
        )
        .where(DnsQuery.response.isnot(None), DnsQuery.response != "")
        .group_by(DnsQuery.query, DnsQuery.response)
    ).all()
    for r in rows:
        edges.append(_edge(
            "domain", r.query, "RESOLVES_TO", "ip", r.response, weight=r.c,
            first=r.mn, last=r.mx_ts,
        ))

    # --- files (malware scans) --------------------------------------------
    rows = db.execute(
        select(
            FileScan.sha256, FileScan.file_name, FileScan.is_malicious,
            func.count().label("c"), func.min(FileScan.scanned_at).label("mn"),
            func.max(FileScan.scanned_at).label("mx_ts"),
        )
        .where(FileScan.sha256.isnot(None), FileScan.sha256 != "")
        .group_by(FileScan.sha256, FileScan.file_name, FileScan.is_malicious)
    ).all()
    for r in rows:
        risk = 95.0 if r.is_malicious else _intel_risk(db, r.sha256)
        nodes.append(_node(
            "file", r.sha256, risk, label=r.file_name or f"File: {r.sha256[:12]}...",
            events=r.c, props={"sha256": r.sha256, "file_name": r.file_name},
            first=r.mn, last=r.mx_ts,
        ))

    # --- techniques (alerts) ----------------------------------------------
    rows = db.execute(
        select(
            Alert.mitre_id, Alert.mitre_name, func.count().label("c"),
            func.min(Alert.created_at).label("mn"), func.max(Alert.created_at).label("mx_ts"),
        )
        .where(Alert.mitre_id.isnot(None), Alert.mitre_id != "", Alert.mitre_id != "T0000")
        .group_by(Alert.mitre_id, Alert.mitre_name)
    ).all()
    for r in rows:
        nodes.append(_node(
            "technique", r.mitre_id, 40.0, label=f"{r.mitre_id} {r.mitre_name}".strip(),
            alerts=r.c, events=0, props={"mitre_id": r.mitre_id, "mitre_name": r.mitre_name},
            first=r.mn, last=r.mx_ts,
        ))

    # --- user/device -> technique (EXHIBITS) ------------------------------
    rows = db.execute(
        select(
            AlertEventLink.alert_id, NormalizedEvent.user, NormalizedEvent.host,
        )
        .join(NormalizedEvent, NormalizedEvent.id == AlertEventLink.event_id)
    ).all()
    # group in python: link each alert's entities to its technique
    alert_techniques = {
        a.id: a.mitre_id for a in db.scalars(select(Alert)).all() if a.mitre_id and a.mitre_id != "T0000"
    }
    for alert_id, user, host in rows:
        technique = alert_techniques.get(alert_id)
        if not technique:
            continue
        if user and user != "-":
            edges.append(_edge("user", user, "EXHIBITS", "technique", technique))
        if host and host != "-":
            edges.append(_edge("device", host, "EXHIBITS", "technique", technique))

    store.upsert_entities(db, nodes)
    store.upsert_edges(db, edges)
    logger.info(
        "Graph sync complete: %d nodes, %d edges",
        len(nodes), len(edges),
    )
    return {"provider": store.name, "nodes": len(nodes), "edges": len(edges)}


def ingest_batch(db, store: GraphStore, records: list[dict], alerts: list[Alert]) -> None:
    """Cheap per-pipeline-batch upserts to keep the graph fresh."""
    if store.name == "neo4j":
        return
    if not records and not alerts:
        return

    nodes: list[dict] = []
    edges: list[dict] = []

    for rec in records:
        source = rec.get("source")
        user = rec.get("user") or ""
        host = rec.get("host") or ""
        if source == "process" and rec.get("name"):
            nodes.append(_node("process", rec["name"], 0.0, label=f"Process: {rec['name']}"))
            if user:
                edges.append(_edge("process", rec["name"], "RUNS_AS", "user", user))
        elif source == "network":
            proc = rec.get("process") or ""
            ip = rec.get("remote_ip") or ""
            if ip:
                risk = _intel_risk(db, ip)
                nodes.append(_node("ip", ip, risk, label=f"IP: {ip}"))
                if proc:
                    nodes.append(_node("process", proc, 0.0, label=f"Process: {proc}"))
                    edges.append(_edge("process", proc, "CONNECTS_TO", "ip", ip))
        elif source == "dns":
            q = rec.get("query") or ""
            proc = rec.get("process") or ""
            if q:
                risk = _intel_risk(db, q)
                nodes.append(_node("domain", q, risk, label=f"Domain: {q}"))
                if proc:
                    nodes.append(_node("process", proc, 0.0, label=f"Process: {proc}"))
                    edges.append(_edge("process", proc, "QUERIES", "domain", q))
                if rec.get("response"):
                    nodes.append(_node("ip", rec["response"], 0.0, label=f"IP: {rec['response']}"))
                    edges.append(_edge("domain", q, "RESOLVES_TO", "ip", rec["response"]))
        if user and user != "-":
            nodes.append(_node("user", user, 0.0, label=f"User: {user}"))
        if host and host != "-":
            nodes.append(_node("device", host, 0.0, label=f"Device: {host}"))
            if user and user != "-":
                edges.append(_edge("user", user, "LOGON_ON", "device", host))

    for alert in alerts:
        mitre = alert.mitre_id or ""
        if mitre and mitre != "T0000":
            nodes.append(_node(
                "technique", mitre, 40.0,
                label=f"{mitre} {alert.mitre_name}".strip(),
                alerts=1, props={"mitre_id": mitre, "mitre_name": alert.mitre_name},
            ))
            if alert.host and alert.host != "-":
                edges.append(_edge("device", alert.host, "EXHIBITS", "technique", mitre))

    if nodes:
        store.upsert_entities(db, nodes, accumulate=True)
    if edges:
        store.upsert_edges(db, edges, accumulate=True)

    _attribute_alert_actors(db, store, alerts)


def _attribute_alert_actors(db, store: GraphStore, alerts: list[Alert]) -> None:
    """Pipeline fast path: attribute actors from alerts' cached intel verdicts.

    Uses :func:`lookup_indicator` with ``offline=True`` so the pipeline never
    round-trips to online providers - verdicts come from the local cache,
    the embedded IOC baseline or the offline classifier, then get clustered
    into ``threat_actor`` nodes by :mod:`backend.graph.actors`.
    """
    try:
        from backend.graph.actors import upsert_actors
        from backend.threatintel.service import extract_indicators, lookup_indicator

        items: list[dict] = []
        for alert in alerts:
            for ind in extract_indicators(f"{alert.evidence or ''} {alert.name or ''}", limit=6):
                items.append(lookup_indicator(db, ind, offline=True))
        if items:
            upsert_actors(db, store, items)
    except Exception as exc:  # pragma: no cover - graph must never break intake
        logger.warning("Pipeline threat-actor attribution failed: %s", exc)