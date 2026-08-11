"""Prometheus text exposition metrics (dependency-free).

Exposes the platform's operational counters in the standard Prometheus
text format (``# HELP`` / ``# TYPE`` / ``metric{label="value"} value``) so
a scraper (Prometheus / Grafana) can ingest them without installing
``prometheus_client``. Metrics are rendered on demand from the live
database and the collector registry - no background counters to maintain.

Endpoints:
    GET /api/system/metrics    (authenticated)
    GET /metrics               (only when BARAQ_METRICS_PUBLIC=1)
"""
from __future__ import annotations

import time

from sqlalchemy import func, select

from backend.config import DATABASE_URL

#: Registered process start time (module import moment).
_START = time.time()


def _fmt(name: str, labels: dict[str, str] | None, value: float) -> str:
    if not labels:
        return f"{name} {value}"
    escaped = ",".join(
        f"{k}={chr(34)}{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34)).replace(chr(10), chr(92) + 'n')}{chr(34)}"
        for k, v in labels.items()
    )
    return f"{name}{{{escaped}}} {value}"


def _es(name: str, typ: str, help_: str) -> str:
    return f"# HELP {name} {help_}\n# TYPE {name} {typ}"


def _db_size_bytes(session=None) -> float:
    """PostgreSQL database size in bytes (0.0 when unavailable)."""
    from sqlalchemy import text

    try:
        with session or __import__("backend.database.connection", fromlist=["SessionLocal"]).SessionLocal() as db:
            return float(db.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0.0)
    except Exception:  # noqa: BLE001
        return 0.0


def collect_metrics(session=None) -> str:
    """Render the Prometheus text exposition for the current platform state."""
    from backend.analyzers import dashboard as dashboard_mod
    from backend.collectors import CollectorManager
    from backend.database.models import (
        Alert,
        DnsQuery,
        EmailMessage,
        FileScan,
        HttpRequest,
        Incident,
        NetworkConnection,
        NormalizedEvent,
        ProcessRecord,
        UsbDevice,
    )
    from backend.detection.rules_engine import build_rules
    from backend.ml.anomaly import get_detector

    close = session is None
    if session is None:
        from backend.database.connection import SessionLocal

        session = SessionLocal()
    lines: list[str] = []

    def _count(model) -> int:
        return int(session.scalar(select(func.count(model.id))) or 0)

    def _emit(name, typ, help_, labels=None, value=0.0):
        lines.append(_es(name, typ, help_))
        lines.append(_fmt(name, labels, float(value)))

    try:
        # Normalized events, bucketed by channel source within each org + host.
        _emit("baraq_events_total", "counter",
              "Normalized events persisted, per org, host and channel source.")
        rows = session.execute(
            select(
                NormalizedEvent.org, NormalizedEvent.host,
                NormalizedEvent.source, func.count(NormalizedEvent.id),
            ).group_by(
                NormalizedEvent.org, NormalizedEvent.host, NormalizedEvent.source
            )
        ).all()
        if rows:
            for org, host, source, n in rows:
                _emit("baraq_events_total", "counter",
                      "Normalized events persisted, per org, host and channel source.",
                      {"org": org or "system", "host": host or "-", "source": source or "unknown"}, n)
        else:
            _emit("baraq_events_total", "counter",
                  "Normalized events persisted, per org, host and channel source.",
                  {"org": "system", "host": "-", "source": "none"}, 0)

        # Active reporting hosts per org (org owns the fleet of agent hosts).
        _emit("baraq_hosts_total", "gauge",
              "Distinct hosts that have persisted events, per org.")
        host_rows = session.execute(
            select(NormalizedEvent.org, func.count(func.distinct(NormalizedEvent.host)))
            .where(NormalizedEvent.host != "", NormalizedEvent.host != "-")
            .group_by(NormalizedEvent.org)
        ).all()
        if host_rows:
            for org, n in host_rows:
                _emit("baraq_hosts_total", "gauge",
                      "Distinct hosts that have persisted events, per org.",
                      {"org": org or "system"}, n)
        else:
            _emit("baraq_hosts_total", "gauge",
                  "Distinct hosts that have persisted events, per org.",
                  {"org": "system"}, 0)

        for name, help_, model in (
            ("baraq_processes_total", "Process records persisted.", ProcessRecord),
            ("baraq_network_connections_total", "Network connection records persisted.", NetworkConnection),
            ("baraq_dns_queries_total", "DNS query records persisted.", DnsQuery),
            ("baraq_http_requests_total", "HTTP request records persisted.", HttpRequest),
            ("baraq_emails_total", "Email message records persisted.", EmailMessage),
            ("baraq_usb_devices_total", "USB device records persisted.", UsbDevice),
            ("baraq_files_scanned_total", "File scan records persisted.", FileScan),
        ):
            _emit(name, "counter", help_, None, _count(model))

        _emit("baraq_alerts_total", "counter",
              "Alerts created, labelled by org, severity and status.")
        alert_rows = session.execute(
            select(Alert.org, Alert.severity, Alert.status, func.count(Alert.id)).group_by(
                Alert.org, Alert.severity, Alert.status
            )
        ).all()
        if alert_rows:
            for org, severity, status, n in alert_rows:
                _emit("baraq_alerts_total", "counter",
                      "Alerts created, labelled by org, severity and status.",
                      {"org": org or "system", "severity": severity, "status": status}, n)
        else:
            _emit("baraq_alerts_total", "counter",
                  "Alerts created, labelled by org, severity and status.",
                  {"org": "system", "severity": "none", "status": "none"}, 0)

        open_alerts_by_org = session.execute(
            select(Alert.org, func.count(Alert.id))
            .where(Alert.status == "open")
            .group_by(Alert.org)
        ).all()
        if open_alerts_by_org:
            for org, n in open_alerts_by_org:
                _emit("baraq_open_alerts", "gauge",
                      "Current number of open alerts, per org.",
                      {"org": org or "system"}, n)
        else:
            _emit("baraq_open_alerts", "gauge",
                  "Current number of open alerts, per org.",
                  {"org": "system"}, 0)
        open_alerts = int(
            session.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
        )
        _emit("baraq_open_alerts_total", "gauge", "Current number of open alerts (all orgs).",
              None, open_alerts)
        _emit("baraq_incidents_total", "gauge", "Incidents created.", None, _count(Incident))

        try:
            score = dashboard_mod.compute_security_score(session)
        except Exception:  # noqa: BLE001
            score = 0.0
        _emit("baraq_security_score", "gauge", "Current host security score (0..100).", None, score)

        rules = [r for r in build_rules(session) if r.rule_id]
        _emit("baraq_rules_total", "gauge", "Number of detection rules registered.", None,
              len(rules))

        detector = get_detector()
        ready = [b for b in ("login", "process", "network") if b in (detector.models or {})]
        _emit("baraq_ml_streams_ready", "gauge",
              "ML behavior streams with a trained model.", None, len(ready))

        _emit("baraq_collectors_enabled", "gauge", "Collection sources active (0/1 each).")
        manager = CollectorManager()
        for collector in manager.collectors:
            _emit("baraq_collectors_enabled", "gauge",
                  "Collection sources active (0/1 each).",
                  {"collector": collector.name}, 1.0 if collector.enabled() else 0.0)

        _emit("baraq_uptime_seconds", "gauge", "Wall-clock seconds since process start.", None,
              max(0.0, time.time() - _START))
        _emit("baraq_db_size_bytes", "gauge",
              "Size of the PostgreSQL database in bytes.", None,
              _db_size_bytes(session))
    finally:
        if close:
            session.close()
    return "\n".join(lines) + "\n"