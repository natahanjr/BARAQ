"""Prometheus metrics endpoint tests."""
from __future__ import annotations

import pytest

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as test_client:
        yield test_client


def test_authenticated_metrics_endpoint(client):
    resp = client.get("/api/system/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    body = resp.text
    assert "# HELP baraq_events_total" in body
    assert "# TYPE baraq_events_total counter" in body
    assert "baraq_alerts_total{" in body
    assert "baraq_uptime_seconds " in body
    assert "baraq_collectors_enabled{collector=" in body


def test_public_metrics_endpoint_private_by_default(client):
    resp = client.get("/metrics")
    assert resp.status_code == 401


def test_metrics_accepts_bearer_api_key():
    """Prometheus v3 scrapes send the key as Authorization: Bearer."""
    from backend.main import app

    with TestClient(app) as bare:
        ok = bare.get(
            "/api/system/metrics",
            headers={"Authorization": "Bearer baraq-dev-admin"},
        )
        assert ok.status_code == 200
        assert "baraq_events_total" in ok.text
        bad = bare.get(
            "/api/system/metrics",
            headers={"Authorization": "Bearer not-a-real-key"},
        )
        assert bad.status_code == 401


def test_metric_parseability(client):
    body = client.get("/api/system/metrics").text
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        assert " " in line, f"malformed metric line: {line!r}"


def _seed_fleet(db):
    """Seed events across two orgs/hosts plus one open alert in univ-a."""
    from backend.analyzers.normalizer import Normalizer
    from backend.database.models import Alert, NormalizedEvent
    from tests.fixtures import _ts

    normalizer = Normalizer()
    for i in range(4):
        rec = {
            "source": "eventlog", "channel": "Security", "event_id": 4625,
            "timestamp": _ts(-1 - i * 0.1).isoformat(), "user": "administrator",
            "message": f"An account failed to log on. Account Name: administrator ({i}).",
            "raw": {"source_ip": "192.168.99.77", "logon_type": 3},
        }
        norm = normalizer.normalize(rec)
        norm["org"] = "univ-a"
        norm["host"] = f"host-{i % 2}"
        db.add(NormalizedEvent(**norm))
    rec = {
        "source": "eventlog", "channel": "Security", "event_id": 4688,
        "timestamp": _ts(-0.5).isoformat(), "user": "bob",
        "message": "Process terminated.",
        "raw": {"command_line": "cmd.exe"},
    }
    norm = normalizer.normalize(rec)
    norm["org"] = "univ-b"
    norm["host"] = "host-x"
    db.add(NormalizedEvent(**norm))
    db.add(Alert(
        name="Brute Force", severity="high", status="open",
        mitre_id="T1110", org="univ-a", host="host-0",
        evidence="12 failed logons", rule="brute_force",
    ))
    db.commit()


def test_metrics_events_labeled_by_org_and_host(client, db):
    _seed_fleet(db)
    body = client.get("/api/system/metrics").text

    assert 'baraq_events_total{org="univ-a",host="host-0",source="eventlog"}' in body
    assert 'baraq_events_total{org="univ-a",host="host-1",source="eventlog"}' in body
    assert 'baraq_events_total{org="univ-b",host="host-x",source="eventlog"}' in body
    assert 'baraq_hosts_total{org="univ-a"}' in body
    assert 'baraq_hosts_total{org="univ-b"}' in body


def test_metrics_alerts_labeled_by_org_and_open_gauge_per_org(client, db):
    _seed_fleet(db)
    body = client.get("/api/system/metrics").text

    assert 'baraq_alerts_total{org="univ-a",severity="high",status="open"}' in body
    assert 'baraq_open_alerts{org="univ-a"}' in body
    assert 'baraq_open_alerts_total 1' in body
