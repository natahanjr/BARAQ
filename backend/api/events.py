"""Events, processes, network, DNS, HTTP API endpoints."""

from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.database.connection import get_db
from backend.database.models import (
    DnsQuery,
    HttpRequest,
    NetworkConnection,
    NormalizedEvent,
    ProcessRecord,
)
from backend.security import require_auth, tenant_scope

router = APIRouter(prefix="/api", tags=["events"], dependencies=[Depends(require_auth)])


def _is_private_remote_ip(ip: str) -> bool:
    """Return True when ``ip`` is NOT a globally routable address.

    Used by ``list_network`` to bucket a connection as inbound vs
    outbound. Replaces a string-prefix ``LIKE`` test (172.2%, 172.3%,
    10.%) that mismatched public address space (HP/Huawei used
    172.32.0.0/11, public allocations in 172.20.0.0/14, etc.).

    The stdlib ``ipaddress`` module exposes both ``is_private`` (RFC1918
    + CGNAT) and ``is_global`` (the inverse - publicly routable). We
    treat ``not is_global`` as 'internal' so loopback, link-local,
    documentation prefixes, multicast and the various reserved blocks
    are all bucketed correctly.

    Returns False for anything that is not a syntactically valid IP
    address (the SQL ``remote_ip != ""`` filter still excludes empty
    strings).
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not addr.is_global


def _events_scope(request: Request) -> str | None:
    """Tenant predicate for the events table (admin sees all)."""
    return tenant_scope(request)


@router.get("/events")
def list_events(
    request: Request,
    event_id: int | None = None,
    user: str | None = None,
    category: str | None = None,
    anomaly: bool | None = None,
    include_demo: int = Query(0, ge=0, le=1),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    scope = _events_scope(request)
    stmt = select(NormalizedEvent)
    if scope is not None:
        stmt = stmt.where(NormalizedEvent.org == scope)
    if not include_demo:
        stmt = stmt.where(NormalizedEvent.demo.is_(False))
    if event_id:
        stmt = stmt.where(NormalizedEvent.event_id == event_id)
    if user:
        stmt = stmt.where(NormalizedEvent.user.ilike(f"%{user}%"))
    if category:
        stmt = stmt.where(NormalizedEvent.category.ilike(f"%{category}%"))
    if anomaly is not None:
        stmt = stmt.where(NormalizedEvent.is_anomaly == anomaly)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(NormalizedEvent.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [e.to_dict() for e in rows],
    }


@router.get("/events/statistics")
def event_statistics(request: Request, db: Session = Depends(get_db)):
    scope = _events_scope(request)
    stmt_event = select(NormalizedEvent.event_id, func.count(NormalizedEvent.id))
    stmt_category = select(NormalizedEvent.category, func.count(NormalizedEvent.id))
    if scope is not None:
        stmt_event = stmt_event.where(NormalizedEvent.org == scope)
        stmt_category = stmt_category.where(NormalizedEvent.org == scope)
    by_event = db.execute(
        stmt_event.group_by(NormalizedEvent.event_id)
        .order_by(func.count(NormalizedEvent.id).desc())
        .limit(20)
    ).all()
    by_category = db.execute(stmt_category.group_by(NormalizedEvent.category)).all()
    return {
        "by_event_id": [{"event_id": int(r[0]), "count": int(r[1])} for r in by_event],
        "by_category": [{"category": r[0], "count": int(r[1])} for r in by_category],
    }


@router.get("/events/{event_id}")
def get_event(event_id: int, request: Request, db: Session = Depends(get_db)):
    scope = _events_scope(request)
    stmt = select(NormalizedEvent).where(NormalizedEvent.id == event_id)
    if scope is not None:
        stmt = stmt.where(NormalizedEvent.org == scope)
    event = db.scalars(stmt).first()
    if not event:
        raise HTTPException(404, "Event not found")
    return event.to_dict()


@router.get("/processes")
def list_processes(
    limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(ProcessRecord).order_by(ProcessRecord.observed_at.desc()).limit(limit)
    ).all()
    return {"total": len(rows), "items": [p.to_dict() for p in rows]}


@router.get("/network")
def list_network(
    limit: int = Query(500, ge=1, le=2000),
    remote_ip: str | None = None,
    since: str | None = None,
    direction: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(NetworkConnection)
    if remote_ip:
        stmt = stmt.where(NetworkConnection.remote_ip == remote_ip)
    if since:
        from datetime import datetime as _dt

        try:
            since_dt = _dt.fromisoformat(since)
            stmt = stmt.where(NetworkConnection.observed_at >= since_dt)
        except ValueError:
            pass
    if direction == "outbound":
        # local is internal/private, remote is external
        stmt = stmt.where(NetworkConnection.remote_ip != "").where(
            ~NetworkConnection.remote_ip.like("10.%"),
            ~NetworkConnection.remote_ip.like("192.168.%"),
            ~NetworkConnection.remote_ip.like("172.16.%"),
            ~NetworkConnection.remote_ip.like("172.17.%"),
            ~NetworkConnection.remote_ip.like("172.18.%"),
            ~NetworkConnection.remote_ip.like("172.19.%"),
            ~NetworkConnection.remote_ip.like("172.2%"),
            ~NetworkConnection.remote_ip.like("172.3%"),
            ~NetworkConnection.remote_ip.like("127.%"),
            ~NetworkConnection.remote_ip.like("0.%"),
            ~NetworkConnection.remote_ip.like("::1"),
        )
    elif direction == "inbound":
        stmt = stmt.where(NetworkConnection.remote_ip != "").where(
            NetworkConnection.remote_ip.like("10.%"),
            NetworkConnection.remote_ip.like("192.168.%"),
            NetworkConnection.remote_ip.like("172.1%"),
            NetworkConnection.remote_ip.like("127.%"),
        )
    rows = db.scalars(
        stmt.order_by(NetworkConnection.observed_at.desc()).limit(limit)
    ).all()
    return {"total": len(rows), "items": [c.to_dict() for c in rows]}


@router.get("/dns")
def list_dns(
    limit: int = Query(200, ge=1, le=1000),
    process: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(DnsQuery)
    if process:
        stmt = stmt.where(DnsQuery.process.ilike(f"%{process}%"))
    rows = db.scalars(stmt.order_by(DnsQuery.observed_at.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [d.to_dict() for d in rows]}


@router.get("/http")
def list_http(
    limit: int = Query(200, ge=1, le=1000),
    host: str | None = None,
    method: str | None = None,
    db: Session = Depends(get_db),
):
    stmt = select(HttpRequest)
    if host:
        stmt = stmt.where(HttpRequest.host.ilike(f"%{host}%"))
    if method:
        stmt = stmt.where(HttpRequest.method == method.upper())
    rows = db.scalars(stmt.order_by(HttpRequest.observed_at.desc()).limit(limit)).all()
    return {"total": len(rows), "items": [h.to_dict() for h in rows]}


@router.get("/network/stats")
def network_stats(db: Session = Depends(get_db)):
    """Aggregated network stats for the traffic analyzer dashboard."""
    # Total counts
    conn_count = db.scalar(select(func.count(NetworkConnection.id))) or 0
    dns_count = db.scalar(select(func.count(DnsQuery.id))) or 0
    http_count = db.scalar(select(func.count(HttpRequest.id))) or 0

    # Bandwidth totals
    total_sent = (
        db.scalar(select(func.coalesce(func.sum(NetworkConnection.bytes_sent), 0))) or 0
    )
    total_recv = (
        db.scalar(select(func.coalesce(func.sum(NetworkConnection.bytes_recv), 0))) or 0
    )

    # Top remote IPs by connection count
    top_ips = db.execute(
        select(
            NetworkConnection.remote_ip, func.count(NetworkConnection.id).label("cnt")
        )
        .where(NetworkConnection.remote_ip != "")
        .group_by(NetworkConnection.remote_ip)
        .order_by(func.count(NetworkConnection.id).desc())
        .limit(10)
    ).all()

    # Top ports by connection count
    top_ports = db.execute(
        select(
            NetworkConnection.remote_port, func.count(NetworkConnection.id).label("cnt")
        )
        .where(NetworkConnection.remote_port > 0)
        .group_by(NetworkConnection.remote_port)
        .order_by(func.count(NetworkConnection.id).desc())
        .limit(10)
    ).all()

    # Top processes by connection count
    top_processes = db.execute(
        select(NetworkConnection.process, func.count(NetworkConnection.id).label("cnt"))
        .where(NetworkConnection.process != "")
        .group_by(NetworkConnection.process)
        .order_by(func.count(NetworkConnection.id).desc())
        .limit(10)
    ).all()

    # Top DNS query domains
    top_dns = db.execute(
        select(DnsQuery.query, func.count(DnsQuery.id).label("cnt"))
        .group_by(DnsQuery.query)
        .order_by(func.count(DnsQuery.id).desc())
        .limit(10)
    ).all()

    # Top HTTP hosts
    top_hosts = db.execute(
        select(HttpRequest.host, func.count(HttpRequest.id).label("cnt"))
        .where(HttpRequest.host != "")
        .group_by(HttpRequest.host)
        .order_by(func.count(HttpRequest.id).desc())
        .limit(10)
    ).all()

    # Connection state distribution
    state_dist = db.execute(
        select(NetworkConnection.state, func.count(NetworkConnection.id).label("cnt"))
        .where(NetworkConnection.state != "")
        .group_by(NetworkConnection.state)
        .order_by(func.count(NetworkConnection.id).desc())
    ).all()

    return {
        "counts": {"connections": conn_count, "dns": dns_count, "http": http_count},
        "bandwidth": {"bytes_sent": total_sent, "bytes_recv": total_recv},
        "top_ips": [{"ip": r[0], "count": r[1]} for r in top_ips],
        "top_ports": [{"port": r[0], "count": r[1]} for r in top_ports],
        "top_processes": [{"process": r[0], "count": r[1]} for r in top_processes],
        "top_dns": [{"query": r[0], "count": r[1]} for r in top_dns],
        "top_hosts": [{"host": r[0], "count": r[1]} for r in top_hosts],
        "state_distribution": [{"state": r[0], "count": r[1]} for r in state_dist],
    }


@router.get("/network/geo")
def ip_geo(ip: str = Query(...)):
    """Lightweight IP geolocation / classification enrichment (no external calls).

    Returns country/region/org heuristics for external IPs so the UI can show
    context without leaking data to third parties.
    """
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False, "classification": "unknown"}

    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
        classification = "internal"
    elif addr.is_multicast:
        classification = "multicast"
    else:
        classification = "external"

    # Heuristic org tagging by well-known ranges (no network egress)
    org = "Unknown"
    asn_hint = ""
    ip_str = str(addr)
    if classification == "external":
        if ip_str.startswith(("13.107", "52.96", "204.79.197")):
            org = "Microsoft"
        elif ip_str.startswith(("142.250", "142.251", "172.217", "216.58")):
            org = "Google"
        elif ip_str.startswith(("149.154", "91.108")):
            org = "Telegram"
        elif ip_str.startswith(("162.159", "104.16", "172.64")):
            org = "Cloudflare"
        elif ip_str.startswith(("20.190", "20.86", "40.1")):
            org = "Azure"
        elif ip_str.startswith(("52.123", "52.110")):
            org = "Microsoft 365"
        elif ip_str.startswith(("135.116", "13.107")):
            org = "Microsoft"
        elif ip_str.startswith(("98.66", "20.86")):
            org = "Azure"
        elif ip_str.startswith(("140.82", "199.232")):
            org = "GitHub"
        elif ip_str.startswith(("173.194", "74.125")):
            org = "Google"

    return {
        "ip": ip,
        "valid": True,
        "classification": classification,
        "version": addr.version,
        "org": org,
        "asn_hint": asn_hint,
        "private": addr.is_private,
    }
