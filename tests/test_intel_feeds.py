"""Threat-intel feed ingestion (roadmap 4.3): STIX/TAXII/MISP parsing,
IOC matching, refresh flow + API endpoints."""

from __future__ import annotations

from backend.database.models import ThreatIntelFeedState, ThreatIntelRecord


# ---------------------------------------------------------------------------
# Parsers (pure)
# ---------------------------------------------------------------------------
def test_parse_stix_pattern_ip_and_domain():
    from backend.intel.feeds import parse_stix_pattern

    found = parse_stix_pattern(
        "[domain-name:value = 'evil.example.com'] AND "
        "[ipv4-addr:value = '185.220.101.45']"
    )
    assert ("domain", "evil.example.com", "") in found
    assert ("ip", "185.220.101.45", "") in found


def test_parse_stix_pattern_file_hash():
    from backend.intel.feeds import parse_stix_pattern

    found = parse_stix_pattern(
        "[file:hashes.SHA-256 = 'a" + "f" * 62 + "'] OR "
        "[file:hashes.'MD5' = '" + "b" * 32 + "']"
    )
    algos = {algo for _k, _v, algo in found}
    assert {"SHA-256", "MD5"} <= algos
    assert all(kind == "hash" for kind, _v, _a in found)


def test_parse_stix_pattern_url_taken_as_domain():
    from backend.intel.feeds import parse_stix_pattern

    found = parse_stix_pattern("[url:value = 'http://phish.example.com/login']")
    assert ("domain", "phish.example.com", "") in found


def test_parse_stix_pattern_ignores_other_objects():
    from backend.intel.feeds import parse_stix_pattern

    assert parse_stix_pattern("[email-addr:value = 'x@y.z']") == []


def test_misp_attributes_flatten():
    from backend.intel.feeds import _misp_attributes

    data = {
        "response": {
            "Attribute": [
                {
                    "type": "ip-dst",
                    "value": "203.0.113.9",
                    "category": "Network activity",
                },
                {"type": "sha256", "value": "c" * 64, "category": "Artifacts dropped"},
                {
                    "type": "url",
                    "value": "https://bad.example.net/x",
                    "category": "Payload delivery",
                },
                {"type": "email-src", "value": "x@y.z", "category": "Payload delivery"},
            ]
        }
    }
    flat = _misp_attributes(data)
    assert ("ip", "203.0.113.9", "Network activity", 0.8) in flat
    assert ("hash", "c" * 64, "Artifacts dropped", 0.8) in flat
    assert ("domain", "bad.example.net", "Payload delivery", 0.8) in flat
    assert len(flat) == 3


# ---------------------------------------------------------------------------
# Refresh flow (network mocked)
# ---------------------------------------------------------------------------
def test_refresh_feeds_upserts_and_is_idempotent(db, monkeypatch):
    import backend.intel.feeds as feeds_mod
    from backend.config import THREAT_INTEL_FEEDS

    if not THREAT_INTEL_FEEDS:
        monkeypatch.setattr(
            feeds_mod,
            "THREAT_INTEL_FEEDS",
            [{"name": "test-feed", "type": "csv", "url": "https://feed.test/iocs.txt"}],
        )

    def fake_fetch(sub):
        return [
            ("ip", "203.0.113.77", "test IOC", 0.85),
            ("domain", "evil.test", "test IOC", 0.85),
        ]

    monkeypatch.setattr(feeds_mod, "fetch_feed", fake_fetch)
    first = feeds_mod.refresh_feeds(db)
    assert first["enabled"] is True
    assert first["feeds"][0]["status"] == "ok"
    assert first["feeds"][0]["iocs"] == 2

    rows = db.query(ThreatIntelRecord).all()
    assert len(rows) == 2
    ip_row = (
        db.query(ThreatIntelRecord)
        .filter(ThreatIntelRecord.indicator == "203.0.113.77")
        .one()
    )
    assert ip_row.category == "malicious"
    assert ip_row.sources == ["csv:test-feed"]

    state = (
        db.query(ThreatIntelFeedState)
        .filter(ThreatIntelFeedState.name == "test-feed")
        .one()
    )
    assert state.ioc_count == 2
    assert state.total_fetched == 2
    assert state.last_success_at is not None

    second = feeds_mod.refresh_feeds(db)
    assert second["feeds"][0]["inserted"] == 0
    assert second["feeds"][0]["updated"] == 2
    assert db.query(ThreatIntelRecord).count() == 2


def test_refresh_feeds_never_downgrades_existing_record(db, monkeypatch):
    import backend.intel.feeds as feeds_mod

    db.add(
        ThreatIntelRecord(
            indicator="203.0.113.88",
            kind="ip",
            category="benign",
            label="old",
            confidence=0.9,
            sources=["old-src"],
        )
    )
    db.commit()

    monkeypatch.setattr(
        feeds_mod,
        "THREAT_INTEL_FEEDS",
        [{"name": "t", "type": "csv", "url": "https://feed.test/iocs.txt"}],
    )
    monkeypatch.setattr(
        feeds_mod,
        "fetch_feed",
        lambda sub: [("ip", "203.0.113.88", "new", 0.5)],
    )
    feeds_mod.refresh_feeds(db)
    row = (
        db.query(ThreatIntelRecord)
        .filter(ThreatIntelRecord.indicator == "203.0.113.88")
        .one()
    )
    assert row.category == "malicious"  # category upgraded
    assert row.confidence == 0.9  # confidence never downgraded


def test_refresh_feeds_reports_error(db, monkeypatch):
    import backend.intel.feeds as feeds_mod

    monkeypatch.setattr(
        feeds_mod,
        "THREAT_INTEL_FEEDS",
        [{"name": "dead", "type": "csv", "url": "https://feed.test/iocs.txt"}],
    )
    monkeypatch.setattr(feeds_mod, "fetch_feed", lambda sub: [])
    summary = feeds_mod.refresh_feeds(db)
    assert summary["feeds"][0]["status"] == "error"
    state = (
        db.query(ThreatIntelFeedState).filter(ThreatIntelFeedState.name == "dead").one()
    )
    assert state.last_error


def test_feed_state_skipped_when_disabled(db, monkeypatch):
    import backend.intel.feeds as feeds_mod

    monkeypatch.setattr(feeds_mod, "THREAT_INTEL_ENABLED", False)
    summary = feeds_mod.refresh_feeds(db)
    assert summary == {"enabled": False, "feeds": []}


# ---------------------------------------------------------------------------
# IOC matching
# ---------------------------------------------------------------------------
def test_match_text_finds_known_iocs_only(db):
    from backend.intel.feeds import match_text

    db.add(
        ThreatIntelRecord(
            indicator="203.0.113.66",
            kind="ip",
            category="malicious",
            label="known bad",
            confidence=0.9,
            sources=["csv:test"],
        )
    )
    db.add(
        ThreatIntelRecord(
            indicator="ok.example.net",
            kind="domain",
            category="benign",
            label="fine",
            confidence=0.9,
            sources=["test"],
        )
    )
    db.commit()

    matches = match_text(db, "connection from 203.0.113.66 to ok.example.net")
    assert [m["indicator"] for m in matches] == ["203.0.113.66"]


def test_match_text_respects_confidence_floor(db, monkeypatch):
    import backend.intel.feeds as feeds_mod

    monkeypatch.setattr(
        feeds_mod,
        "THREAT_INTEL_FEED_MIN_CONFIDENCE",
        0.9,
    )
    db.add(
        ThreatIntelRecord(
            indicator="203.0.113.55",
            kind="ip",
            category="malicious",
            label="low conf",
            confidence=0.6,
            sources=["csv:test"],
        )
    )
    db.commit()
    assert feeds_mod.match_text(db, "hit 203.0.113.55") == []


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------
def test_intel_endpoints():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-admin"}) as client:
        r = client.get("/api/intel/feeds")
        assert r.status_code == 200
        assert "feeds" in r.json()
        r = client.post("/api/intel/feeds/refresh")
        assert r.status_code == 200, r.text
        assert "feeds" in r.json()
        r = client.post("/api/intel/match", json={"text": "nope.example.com"})
        assert r.status_code == 200
        assert "matches" in r.json()
        r = client.post("/api/intel/lookup", json={"indicator": "203.0.113.9"})
        assert r.status_code == 200
        assert r.json()["kind"] == "ip"


def test_intel_refresh_requires_admin():
    from fastapi.testclient import TestClient

    from backend.main import app

    with TestClient(app, headers={"X-API-Key": "baraq-dev-analyst"}) as client:
        r = client.post("/api/intel/feeds/refresh")
        assert r.status_code == 403
