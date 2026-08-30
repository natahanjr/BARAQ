"""Observability (roadmap 5.2): SLO gauges + optional OpenTelemetry export.

* :func:`slo_metrics` renders Prometheus gauges for the configured SLOs
  (``BARAQ_SLO_DEFINITIONS``) with live health computed from the database -
  availability of the ML tier, data freshness (ingestion lag), alert-volume
  burn. Grafana uses these for error-budget panels.
* :func:`setup_observability` lazily starts an OpenTelemetry OTLP/HTTP
  tracer + metrics exporter when ``BARAQ_OTEL_ENDPOINT`` is set and the
  ``opentelemetry`` SDK is installed. Without either, it is a no-op - the
  platform never hard-depends on OTel.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC

from sqlalchemy import func, select

from backend.config import OTEL_ENDPOINT, SLO_DEFINITIONS

logger = logging.getLogger("baraq.observability")

_START = time.time()
_otel_started = False


def _parse_slo(definition: str) -> tuple[str, str, float] | None:
    """Parse ``name=window=target`` -> (name, window_hours, target_ratio)."""
    try:
        name, window, target = definition.split("=")
        window = window.strip()
        if window.endswith("d"):
            hours = int(window[:-1]) * 24
        elif window.endswith("h"):
            hours = int(window[:-1])
        elif window.endswith("m"):
            hours = int(window[:-1]) // 60
        else:
            hours = int(window)
        return name.strip(), hours, float(target)
    except (ValueError, AttributeError):
        return None


def _slo_freshness(session) -> tuple[float, float]:
    """(fresh_ratio, last_lag_hours) for the freshness SLO.

    Fresh events are those whose ``timestamp`` is at most 24 h behind the
    newest event in the database. A database with no events scores 0.0.
    """
    from datetime import datetime, timedelta

    from backend.database.models import NormalizedEvent

    newest = session.scalar(select(func.max(NormalizedEvent.timestamp)))
    if not newest:
        return 0.0, 0.0
    lag = max(0.0, (datetime.now(UTC) - newest).total_seconds() / 3600.0)
    cutoff = newest - timedelta(hours=24)
    fresh = int(
        session.scalar(
            select(func.count(NormalizedEvent.id)).where(
                NormalizedEvent.timestamp >= cutoff
            )
        )
        or 0
    )
    total = int(session.scalar(select(func.count(NormalizedEvent.id))) or 0)
    return (fresh / total if total else 0.0), lag


def _slo_alert_volume(session, hours: int) -> float:
    """Ratio of the last ``hours`` of alerts that were auto-resolved / triaged.

    Burn is measured as the share of alerts still open - a high burn means
    the analyst queue is backing up. Returns 1.0 when no alerts exist.
    """
    from datetime import datetime, timedelta

    from backend.database.models import Alert

    since = datetime.now(UTC) - timedelta(hours=hours)
    total = int(
        session.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since))
        or 0
    )
    if total == 0:
        return 1.0
    open_alerts = int(
        session.scalar(
            select(func.count(Alert.id)).where(
                Alert.created_at >= since, Alert.status == "open"
            )
        )
        or 0
    )
    return 1.0 - (open_alerts / total)


def slo_metrics(session) -> list[str]:
    """Render the SLO gauges for the Prometheus exposition."""
    from backend.ml.anomaly import get_detector

    lines: list[str] = []
    detector = get_detector()
    for definition in SLO_DEFINITIONS:
        parsed = _parse_slo(definition)
        if parsed is None:
            continue
        name, hours, target = parsed
        if name == "availability":
            value = 1.0 if detector.is_ready else 0.0
        elif name == "freshness":
            value, _lag = _slo_freshness(session)
        elif name == "alert_volume":
            value = _slo_alert_volume(session, hours)
        else:
            continue
        lines.append(
            "# HELP baraq_slo_health Ratio of the SLO met in its window (1.0 = healthy)."
        )
        lines.append("# TYPE baraq_slo_health gauge")
        lines.append(
            f'baraq_slo_health{{name="{name}",window_hours="{hours}"}} {value:.4f}'
        )
        lines.append("# HELP baraq_slo_target Declared error-budget target.")
        lines.append("# TYPE baraq_slo_target gauge")
        lines.append(
            f'baraq_slo_target{{name="{name}",window_hours="{hours}"}} {target:.4f}'
        )
    return lines


def setup_observability() -> bool:
    """Start the OTel OTLP exporter when configured and available.

    Returns True when an exporter was started, False when the feature is
    disabled or the SDK is missing (the normal case - never an error).
    """
    global _otel_started
    if _otel_started:
        return True
    if not OTEL_ENDPOINT:
        return False
    try:
        from opentelemetry import trace as _trace  # type: ignore[import-not-found]
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-not-found]
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace import TracerProvider  # type: ignore[import-not-found]
        from opentelemetry.sdk.trace.export import (  # type: ignore[import-not-found]
            BatchSpanProcessor,
        )

        provider = TracerProvider(
            resource=Resource.create({"service.name": "baraq-soc"})
        )
        provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=OTEL_ENDPOINT + "/v1/traces"))
        )
        _trace.set_tracer_provider(provider)
        logger.info("OpenTelemetry traces enabled -> %s", OTEL_ENDPOINT)
        _otel_started = True
        return True
    except Exception as exc:
        logger.warning(
            "OpenTelemetry disabled (%s); install opentelemetry-* to enable", exc
        )
        return False
