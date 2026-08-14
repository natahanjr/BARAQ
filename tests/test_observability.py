"""Observability (roadmap 5.2): SLO gauges, JSON logging, metrics endpoint."""
from __future__ import annotations


def test_slo_parse():
    from backend.observability import _parse_slo

    assert _parse_slo("availability=30d=0.99") == ("availability", 720, 0.99)
    assert _parse_slo("freshness=24h=0.95") == ("freshness", 24, 0.95)
    assert _parse_slo("garbage") is None


def test_slo_metrics_renders_targets_and_health(db):
    from backend.observability import slo_metrics

    lines = slo_metrics(db)
    rendered = "\n".join(lines)
    assert "baraq_slo_health{" in rendered
    assert "baraq_slo_target{" in rendered
    assert "availability" in rendered


def test_slo_alert_volume_empty_db_is_healthy(db):
    from backend.observability import _slo_alert_volume

    assert _slo_alert_volume(db, 24) == 1.0


def test_metrics_endpoint_includes_slo():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/system/metrics")
        assert r.status_code == 200
        body = r.text
        assert "baraq_slo_health" in body
        assert "baraq_slo_target" in body
        assert "baraq_uptime_seconds" in body
        assert "baraq_security_score" in body


def test_json_log_formatter_emits_valid_json():
    import json
    import logging

    from backend.logging_config import JSONFormatter

    record = logging.LogRecord(
        "baraq.test", logging.INFO, "file.py", 1, "hello %s", ({"x": 1},), None
    )
    payload = json.loads(JSONFormatter().format(record))
    assert payload["level"] == "INFO"
    assert payload["logger"] == "baraq.test"
    assert payload["message"] == "hello {'x': 1}"


def test_otel_noop_without_endpoint(monkeypatch):
    import backend.observability as obs_mod

    monkeypatch.setattr(obs_mod, "OTEL_ENDPOINT", "")
    assert obs_mod.setup_observability() is False