"""Test collectors: live collectors and collector manager wiring."""
from __future__ import annotations

from backend.collectors import CollectorManager
from backend.collectors.dns_http import DnsHttpCollector
from backend.collectors.email import EmailCollector
from backend.collectors.malware import MalwareFileCollector
from backend.collectors.usb import UsbCollector
from tests.fixtures import brute_force, port_scan, suspicious_powershell


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
