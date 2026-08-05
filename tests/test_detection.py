"""Test normalizer + detection rules against deterministic fixture records."""
from __future__ import annotations

import pytest

from backend.analyzers.normalizer import Normalizer
from backend.database.models import NetworkConnection, NormalizedEvent
from tests.fixtures import (
    add_normalized,
    benign_baseline,
    brute_force,
    data_staging,
    http_exfil,
    logon_failure,
    lateral_movement,
    persistence,
    phishing_email,
    port_scan,
    privilege_escalation,
    suspicious_powershell,
    usb_device,
)


@pytest.mark.parametrize(
    "record,expected_event_id,category",
    [
        (logon_failure(), 4625, "Authentication"),
        (privilege_escalation()[0], 4720, "Account Management"),
        (persistence()[0], 7045, "Service"),
        (suspicious_powershell()[0], 4104, "PowerShell"),
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
    out = Normalizer().normalize(logon_failure())
    assert out["user"] == "administrator"
    assert out["raw_json"]["facts"]["source_ip"] == "192.168.99.77"


def test_normalize_batch_counts():
    records = brute_force() + suspicious_powershell()
    out = Normalizer().normalize_batch(records)
    assert len(out) == len(records)


def test_brute_force_detection(db):
    from backend.detection.rules.brute_force import BruteForceRule

    add_normalized(db, brute_force(attempts=12))
    findings = BruteForceRule(db, threshold=5).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1110"
    assert len(findings[0].event_ids) == 12


def test_powershell_detection(db):
    from backend.detection.rules.powershell import SuspiciousPowerShellRule

    add_normalized(db, suspicious_powershell())
    findings = SuspiciousPowerShellRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1059.001"
    assert findings[0].severity in ("high", "critical")


def test_persistence_detection(db):
    from backend.detection.rules.persistence import PersistenceRule

    add_normalized(db, persistence())
    findings = PersistenceRule(db).evaluate(10)
    assert len(findings) == 2  # service + scheduled task
    assert all(f.mitre_id == "T1547" for f in findings)


def test_port_scan_detection(db):
    from backend.detection.rules.network_recon import NetworkReconRule

    for r in port_scan(ports=30):
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
    from backend.detection.rules.brute_force import BruteForceRule
    from backend.detection.rules.powershell import SuspiciousPowerShellRule

    add_normalized(db, benign_baseline(150))
    assert BruteForceRule(db, threshold=5).evaluate(10) == []
    assert SuspiciousPowerShellRule(db).evaluate(10) == []


def test_lateral_movement_smb_detection(db):
    from backend.detection.rules.lateral_movement import LateralMovementRule

    for r in lateral_movement():
        db.add(NetworkConnection(
            pid=r["pid"], process=r["process"], local_ip=r["local_ip"],
            local_port=r["local_port"], remote_ip=r["remote_ip"],
            remote_port=r["remote_port"], state=r["state"],
            is_listening=r["is_listening"],
            observed_at=Normalizer._safe_ts(r["timestamp"]),
        ))
    db.commit()
    findings = LateralMovementRule(db, admin_share_threshold=3).evaluate(10)
    assert len(findings) > 0
    assert findings[0].mitre_id == "T1021"


def test_data_staging_archive_tool_detection(db):
    from backend.detection.rules.data_staging import DataStagingRule

    add_normalized(db, data_staging())
    findings = DataStagingRule(db).evaluate(10)
    assert len(findings) > 0
    assert findings[0].mitre_id == "T1074"


def test_malware_file_rule(db):
    from backend.database.models import FileScan
    from backend.detection.rules.malware_file import MalwareFileRule
    from datetime import datetime, timezone

    db.add(FileScan(
        file_path="C:\\Users\\Public\\beacon.exe", file_name="beacon.exe",
        sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        size=12345, signed=False, is_malicious=True, signature_name="known-bad-sample",
        scanned_at=datetime.now(timezone.utc),
    ))
    db.commit()
    findings = MalwareFileRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1105"


def test_email_phishing_rule(db):
    from backend.database.models import EmailMessage
    from backend.detection.rules.email_phishing import EmailPhishingRule
    from datetime import datetime, timezone

    db.add(EmailMessage(
        sender="noreply@accounts-update.tk", recipient="alice@corp.local",
        subject="URGENT: verify your account password now",
        body="Click https://evil.tk/login to verify. Attachment: invoice.exe",
        attachment_types=".exe", ip_address="203.0.113.7",
        received_at=datetime.now(timezone.utc),
    ))
    db.commit()
    findings = EmailPhishingRule(db, threshold=2.0).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1566"


def test_usb_device_rule(db):
    from backend.database.models import UsbDevice
    from backend.detection.rules.usb import UsbDeviceRule
    from datetime import datetime, timezone

    db.add(UsbDevice(
        device_name="Kingston DataTraveler", device_id="USB\\VID_0951&PID_1666",
        vendor="Kingston", serial="07018AC27C", inserted_at=datetime.now(timezone.utc),
    ))
    db.commit()
    findings = UsbDeviceRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1091"


def test_dns_http_exfil_rule(db):
    from backend.database.models import DnsQuery, HttpRequest
    from backend.detection.rules.dns_http import DnsHttpExfilRule
    from datetime import datetime, timezone

    for q in dns_exfil_for_db():
        db.add(DnsQuery(
            process="svchost.exe", pid=500, query=q, response="8.8.4.4",
            response_size=600, observed_at=datetime.now(timezone.utc),
        ))
    db.add(HttpRequest(
        process="powershell.exe", pid=1234, method="POST", url="https://evil.xyz/upload",
        host="evil.xyz", status_code=200, request_body_size=2_000_000,
        response_body_size=5_000_000, observed_at=datetime.now(timezone.utc),
    ))
    db.commit()
    findings = DnsHttpExfilRule(db).evaluate(10)
    assert len(findings) >= 1
    assert all(f.mitre_id == "T1071" for f in findings)


def dns_exfil_for_db():
    return [f"data{i}.evil.xyz" for i in range(25)]


def test_kill_chain_correlation(db):
    from backend.database.models import Alert
    from backend.detection.rules.correlation import KillChainCorrelationRule
    from datetime import datetime, timezone

    for name, rule in (
        ("Brute Force Attack", "brute_force"),
        ("Persistence Mechanism Installed", "persistence"),
        ("Suspicious Privilege Escalation", "privilege_escalation"),
    ):
        db.add(Alert(
            name=name, rule=rule, status="open", severity="high", mitre_id="T1110",
            mitre_name="Brute Force", mitre_tactic="Credential Access",
            evidence="Brute force detected for account 'administrator' from 192.168.99.77.",
            created_at=datetime.now(timezone.utc),
        ))
    db.commit()
    findings = KillChainCorrelationRule(db, threshold=2).evaluate(10)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
