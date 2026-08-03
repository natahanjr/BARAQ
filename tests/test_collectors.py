"""Test Phase 1 collectors: simulated attack data production."""
from __future__ import annotations

import pytest

from backend.collectors.simulator import (
    AttackSimulator,
    gen_brute_force,
    gen_baseline_events,
    gen_persistence,
    gen_port_scan,
    gen_privilege_escalation,
    gen_suspicious_powershell,
)


def test_full_suite_produces_all_event_types():
    records = AttackSimulator().collect()
    sources = {r["source"] for r in records}
    assert {"eventlog", "powershell", "network"} <= sources


@pytest.mark.parametrize(
    "generator,event_id,count",
    [
        (gen_brute_force, 4625, 12),
        (gen_suspicious_powershell, 4104, 1),
        (gen_privilege_escalation, 4720, 1),
        (gen_persistence, 7045, 1),
    ],
)
def test_scenario_shapes(generator, event_id, count):
    records = generator()
    matching = [r for r in records if r["event_id"] == event_id]
    assert len(matching) == count


def test_port_scan_has_distinct_ports():
    records = gen_port_scan(ports=30)
    ports = {r["remote_port"] for r in records}
    assert len(ports) == 30
    assert all(r["state"] == "SYN_SENT" for r in records)


def test_powershell_encoded_payload():
    records = gen_suspicious_powershell()
    raw = records[0]["raw"]
    assert raw["has_encoded"] is True
    assert raw["has_download"] is True
    assert raw["has_hidden"] is True


def test_baseline_has_no_attacks():
    records = gen_baseline_events(100)
    assert all(r.get("event_id", 0) not in (7045, 4698, 4720) for r in records)
    assert all(r.get("process") != "nmap.exe" for r in records)


def test_unknown_scenario_raises():
    sim = AttackSimulator()
    with pytest.raises(KeyError):
        sim.scenario("does_not_exist")
