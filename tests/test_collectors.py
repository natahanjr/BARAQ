"""Test collectors: live collectors and collector manager wiring."""
from __future__ import annotations

import pytest

from backend.collectors import CollectorManager
from backend.collectors.dns_http import DnsHttpCollector
from backend.collectors.email import EmailCollector
from backend.collectors.malware import MalwareFileCollector
from backend.collectors.usb import UsbCollector
from tests.fixtures import brute_force, port_scan, suspicious_powershell


@pytest.fixture
def clean_health_registry():
    """Isolate the process-wide collector-health singleton per test."""
    from backend.collectors.health import registry

    registry.reset()
    yield registry
    registry.reset()


def test_collector_manager_registers_live_collectors():
    manager = CollectorManager()
    names = {c.name for c in manager.collectors}
    assert {"eventlog", "powershell", "process", "network", "dns_http", "email", "usb", "malware"} <= names
    assert "simulator" not in names


def test_email_collector_disabled_without_dir():
    collector = EmailCollector(ingest_dir="")
    assert collector.enabled() is False
    assert collector.collect() == []


def test_usb_collector_graceful_without_pywin32():
    collector = UsbCollector()
    assert collector.collect() in ([], None) or isinstance(collector.collect(), list)


def test_dns_http_graceful_without_sources():
    collector = DnsHttpCollector()
    assert isinstance(collector.collect(), list)


def test_malware_collector_has_signatures():
    collector = MalwareFileCollector()
    assert collector.enabled()
    assert isinstance(collector.collect(), list)


def test_malware_collector_ignores_empty_files(monkeypatch, tmp_path):
    """Regression: the SHA-256 of a 0-byte file (e3b0c442...) must never be
    treated as malware - an empty download stub (e.g. Claude-*.msix) is not a
    threat and must not produce a malicious file record."""
    import backend.collectors.malware as malware_mod

    empty = tmp_path / "Claude-2436373788.msix"
    empty.write_bytes(b"")

    monkeypatch.setattr(malware_mod, "SCAN_TARGETS", ((str(tmp_path), 50),))
    collector = MalwareFileCollector()
    records = collector.collect()

    names = [r["file_name"] for r in records]
    assert "Claude-2436373788.msix" in names, "test file not scanned"
    for r in records:
        assert r["is_malicious"] is False
        assert r["signature_name"] == ""
        assert r["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_malware_collector_still_flags_real_bad_hash(monkeypatch, tmp_path):
    """A genuinely known-bad signature still fires after the empty-file fix."""
    import hashlib
    import json

    import backend.collectors.malware as malware_mod

    bad = tmp_path / "payload.bin"
    bad.write_bytes(b"evil-01")
    digest = hashlib.sha256(bad.read_bytes()).hexdigest()

    sig = tmp_path / "signatures.json"
    sig.write_text(
        json.dumps({"hashes": {digest: "known-bad-sample"}, "paths": [], "malware_names": []}),
        encoding="utf-8",
    )
    monkeypatch.setattr(malware_mod, "SCAN_TARGETS", ((str(tmp_path), 50),))
    collector = MalwareFileCollector(signature_list=sig)
    records = collector.collect()
    assert any(r["is_malicious"] for r in records)
    assert any(r["signature_name"] == "known-bad-sample" for r in records)


def test_fixtures_produce_eventlog_records():
    records = brute_force()
    assert all(r["source"] == "eventlog" for r in records[:12])
    assert all(r["event_id"] == 4625 for r in records[:12])


def test_fixtures_port_scan_records():
    records = port_scan(ports=30)
    assert {r["remote_port"] for r in records} == {1 + (i * 137) % 65535 for i in range(30)}
    assert all(r["state"] == "SYN_SENT" for r in records)


def test_fixtures_powershell_encoded():
    records = suspicious_powershell()
    assert records[0]["raw"]["has_encoded"] is True
    assert records[0]["raw"]["has_download"] is True


def test_health_registry_tracks_channels(clean_health_registry):
    """Per-channel success/failure counters drive the /collectors/health API."""
    registry = clean_health_registry

    registry.record_success("Security", 5)
    registry.record_failure("Security", "boom")
    snap = {c["channel"]: c for c in registry.snapshot()}
    assert snap["Security"]["records_total"] == 5
    assert snap["Security"]["consecutive_failures"] == 1
    assert snap["Security"]["ok"] is False
    assert snap["Security"]["last_error"] == "boom"

    registry.record_success("Security", 1)
    snap = {c["channel"]: c for c in registry.snapshot()}
    assert snap["Security"]["ok"] is True
    assert snap["Security"]["consecutive_failures"] == 0
    assert registry.unhealthy() == []


def test_health_permission_error_marked(clean_health_registry):
    from backend.collectors.health import PRIVILEGE_NOT_HELD

    registry = clean_health_registry

    registry.record_failure("Security", "1314", permission_issue=True)
    snap = {c["channel"]: c for c in registry.snapshot()}
    assert snap["Security"]["permission_issue"] is True


def test_retry_with_backoff_transient_then_success(monkeypatch):
    import backend.collectors.health as health_mod

    monkeypatch.setattr(health_mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def flaky_then_ok():
        calls["n"] += 1
        if calls["n"] < 3:
            raise OSError("channel busy")
        return "data"

    assert health_mod.retry_with_backoff(flaky_then_ok, attempts=3) == "data"
    assert calls["n"] == 3


def test_retry_privilege_error_raises_immediately(monkeypatch):
    import backend.collectors.health as health_mod

    monkeypatch.setattr(health_mod.time, "sleep", lambda s: None)
    calls = {"n": 0}

    class PrivError(Exception):
        winerror = 1314

    def always_privilege():
        calls["n"] += 1
        raise PrivError("no privilege")

    try:
        health_mod.retry_with_backoff(always_privilege, attempts=3)
        assert False, "expected exception"
    except PrivError:
        assert calls["n"] == 1, "persistent error must not be retried"
