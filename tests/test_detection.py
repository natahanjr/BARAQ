"""Test Phase 2 normalizer + Phase 3 detection rules."""
from __future__ import annotations

import pytest

from backend.analyzers.normalizer import Normalizer
from backend.collectors.simulator import (
    gen_brute_force,
    gen_persistence,
    gen_port_scan,
    gen_privilege_escalation,
    gen_suspicious_powershell,
)


@pytest.mark.parametrize(
    "record,expected_event_id,category",
    [
        (gen_brute_force()[0], 4625, "Authentication"),
        (gen_privilege_escalation()[0], 4720, "Account Management"),
        (gen_persistence()[0], 7045, "Service"),
        (gen_suspicious_powershell()[0], 4104, "PowerShell"),
    ],
)
def test_normalization_shape(record, expected_event_id, category):
    normalized = Normalizer().normalize(record)
    assert normalized["event_id"] == expected_event_id
    assert normalized["category"] == category
    assert normalized["timestamp"] is not None
    assert normalized["user"]
    assert normalized["risk"] in {"Low", "Medium", "High"}


def test_normalizer_extracts_account_from_message():
    record = {
        "source": "eventlog",
        "event_id": 4625,
        "user": "",
        "timestamp": "2026-08-03T10:00:00",
        "message": "An account failed to log on. Account Name: administrator. Source Network Address: 10.0.0.9.",
        "raw": {},
    }
    out = Normalizer().normalize(record)
    assert out["user"] == "administrator"
    assert out["raw_json"]["facts"]["source_ip"] == "10.0.0.9"


def test_normalize_batch_counts():
    records = gen_brute_force() + gen_suspicious_powershell()
    out = Normalizer().normalize_batch(records)
    assert len(out) == len(records)


def test_brute_force_detection(db):
    from backend.detection.rules.brute_force import BruteForceRule

    records = gen_brute_force(attempts=12)
    for r in records:
        db.add(__import__("backend.database.models", fromlist=["NormalizedEvent"]).NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
    findings = BruteForceRule(db, threshold=5).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1110"
    assert len(findings[0].event_ids) == 12


def test_powershell_detection(db):
    from backend.database.models import NormalizedEvent
    from backend.detection.rules.powershell import SuspiciousPowerShellRule

    for r in gen_suspicious_powershell():
        db.add(NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
    findings = SuspiciousPowerShellRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1059.001"
    assert findings[0].severity in ("high", "critical")


def test_persistence_detection(db):
    from backend.database.models import NormalizedEvent
    from backend.detection.rules.persistence import PersistenceRule

    for r in gen_persistence(binary="C:\\Users\\Public\\svchost.exe"):
        db.add(NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
    findings = PersistenceRule(db).evaluate(10)
    assert len(findings) == 2  # service + scheduled task
    assert all(f.mitre_id == "T1547" for f in findings)


def test_port_scan_detection(db):
    from backend.database.models import NetworkConnection
    from backend.detection.rules.network_recon import NetworkReconRule

    for r in gen_port_scan(ports=30):
        db.add(NetworkConnection(
            pid=r["pid"], process=r["process"], local_ip=r["local_ip"],
            local_port=r["local_port"], remote_ip=r["remote_ip"],
            remote_port=r["remote_port"], state=r["state"],
            is_listening=r["is_listening"],
            observed_at=Normalizer._safe_ts(r["timestamp"]),
        ))
    db.commit()
    findings = NetworkReconRule(db, distinct_ports=20, window_seconds=120).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1046"


def test_no_false_positive_on_baseline(db):
    from backend.database.models import NormalizedEvent
    from backend.collectors.simulator import gen_baseline_events
    from backend.detection.rules.brute_force import BruteForceRule
    from backend.detection.rules.powershell import SuspiciousPowerShellRule

    for r in gen_baseline_events(150):
        db.add(NormalizedEvent(**Normalizer().normalize(r)))
    db.commit()
    assert BruteForceRule(db, threshold=5).evaluate(10) == []
    assert SuspiciousPowerShellRule(db).evaluate(10) == []
