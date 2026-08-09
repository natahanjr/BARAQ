"""Prometheus text exposition metrics (dependency-free).

Exposes the platform's operational counters in the standard Prometheus
text format (``# HELP`` / ``# TYPE`` / ``metric{label="value"} value``) so
a scraper (Prometheus / Grafana) can ingest them without installing
``prometheus_client``. Metrics are rendered on demand from the live
database and the collector registry - no background counters to maintain.

Endpoints:
    GET /api/system/metrics    (authenticated)
    GET /metrics               (only when SENTINEL_METRICS_PUBLIC=1)
"""
from __future__ import annotations

import os
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


def _sqlite_path() -> str:
    if DATABASE_URL and DATABASE_URL.startswith("sqlite:///"):
        return DATABASE_URL[len("sqlite:///"):]
    return ""


def _db_size_bytes() -> float:
    path = _sqlite_path()
    if not path or not os.path.exists(path):
        return 0.0
    return float(os.path.getsize(path))


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
        # Normalized events, bucketed by channel/source.
        _emit("sentinel_events_total", "counter", "Normalized events persisted, per channel source.")
        rows = session.execute(
            select(NormalizedEvent.source, func.count(NormalizedEvent.id)).group_by(
                NormalizedEvent.source
            )
        ).all()
        if rows:
            for source, n in rows:
                _emit("sentinel_events_total", "counter",
                      "Normalized events persisted, per channel source.",
                      {"source": source or "unknown"}, n)
        else:
            _emit("sentinel_events_total", "counter",
                  "Normalized events persisted, per channel source.",
                  {"source": "none"}, 0)

        for name, help_, model in (
            ("sentinel_processes_total", "Process records persisted.", ProcessRecord),
            ("sentinel_network_connections_total", "Network connection records persisted.", NetworkConnection),
            ("sentinel_dns_queries_total", "DNS query records persisted.", DnsQuery),
            ("sentinel_http_requests_total", "HTTP request records persisted.", HttpRequest),
            ("sentinel_emails_total", "Email message records persisted.", EmailMessage),
            ("sentinel_usb_devices_total", "USB device records persisted.", UsbDevice),
            ("sentinel_files_scanned_total", "File scan records persisted.", FileScan),
        ):
            _emit(name, "counter", help_, None, _count(model))

        _emit("sentinel_alerts_total", "counter", "Alerts created, labelled by severity and status.")
        alert_rows = session.execute(
            select(Alert.severity, Alert.status, func.count(Alert.id)).group_by(
                Alert.severity, Alert.status
            )
        ).all()
        if alert_rows:
            for severity, status, n in alert_rows:
                _emit("sentinel_alerts_total", "counter",
                      "Alerts created, labelled by severity and status.",
                      {"severity": severity, "status": status}, n)
        else:
            _emit("sentinel_alerts_total", "counter",
                  "Alerts created, labelled by severity and status.",
                  {"severity": "none", "status": "none"}, 0)

        open_alerts = int(
            session.scalar(select(func.count(Alert.id)).where(Alert.status == "open")) or 0
        )
        _emit("sentinel_open_alerts", "gauge", "Current number of open alerts.", None, open_alerts)
        _emit("sentinel_incidents_total", "gauge", "Incidents created.", None, _count(Incident))

        try:
            score = dashboard_mod.compute_security_score(session)
        except Exception:  # noqa: BLE001
            score = 0.0
        _emit("sentinel_security_score", "gauge", "Current host security score (0..100).", None, score)

        rules = [r for r in build_rules(session) if r.rule_id]
        _emit("sentinel_rules_total", "gauge", "Number of detection rules registered.", None,
              len(rules))

        detector = get_detector()
        ready = [b for b in ("login", "process", "network") if b in (detector.models or {})]
        _emit("sentinel_ml_streams_ready", "gauge",
              "ML behavior streams with a trained model.", None, len(ready))

        _emit("sentinel_collectors_enabled", "gauge", "Collection sources active (0/1 each).")
        manager = CollectorManager()
        for collector in manager.collectors:
            _emit("sentinel_collectors_enabled", "gauge",
                  "Collection sources active (0/1 each).",
                  {"collector": collector.name}, 1.0 if collector.enabled() else 0.0)

        _emit("sentinel_uptime_seconds", "gauge", "Wall-clock seconds since process start.", None,
              max(0.0, time.time() - _START))
        _emit("sentinel_db_size_bytes", "gauge",
              "Size of the local SQLite database file (0 for non-SQLite engines).", None,
              _db_size_bytes())
    finally:
        if close:
            session.close()
    return "\n".join(lines) + "\n"