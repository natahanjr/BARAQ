"""Test normalizer + detection rules against deterministic fixture records."""

from __future__ import annotations

from datetime import UTC

import pytest

from backend.analyzers.normalizer import Normalizer
from backend.database.models import NetworkConnection, NormalizedEvent
from tests.fixtures import (
    add_normalized,
    admin_tampering,
    benign_baseline,
    benign_process,
    bits_download,
    brute_force,
    credential_store_theft,
    data_staging,
    hidden_artifact,
    http_volume,
    lateral_movement,
    log_clear,
    logon_failure,
    lolbin_usage,
    masquerading_process,
    persistence,
    port_scan,
    privilege_escalation,
    ransomware_impact,
    recovery_inhibit,
    schtasks_create,
    shortcut_persistence,
    suspicious_powershell,
    sysmon_benign_registry,
    sysmon_lsass_benign,
    sysmon_lsass_dump,
    sysmon_runkey,
    wmi_subscription,
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


def test_normalizer_flags_truncated_process_name():
    """A process path cut short (no executable suffix) is flagged, and the
    missing structured copy marks the process data incomplete."""
    out = Normalizer().normalize(
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4688,
            "timestamp": "2026-08-14T10:00:00+00:00",
            "user": "u",
            "message": "New Process Name:\tC:\\Windows\\Sys",
            "raw": {"record_number": 1, "structured_fetch_failed": True},
        }
    )
    assert out["data_integrity"] == "truncated"
    truncated = out["raw_json"]["data_integrity"]["truncated_fields"]
    assert "new_process" in truncated
    assert "process_data" in truncated


def test_normalizer_flags_bare_drive_letter_process():
    """'New Process Name:\tC' is the SafeFormatMessage truncation signature."""
    out = Normalizer().normalize(
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4688,
            "timestamp": "2026-08-14T10:00:00+00:00",
            "user": "u",
            "message": "New Process Name:\tC",
            "raw": {"record_number": 2},
        }
    )
    truncated = out["raw_json"]["data_integrity"]["truncated_fields"]
    assert "new_process" in truncated


def test_normalizer_flags_message_cap():
    """Messages over the length cap are flagged as lossy."""
    out = Normalizer().normalize(
        {
            "source": "agent",
            "event_id": 4625,
            "timestamp": "2026-08-14T10:00:00+00:00",
            "user": "u",
            "message": "x" * 9000,
            "raw": {"record_number": 3},
        }
    )
    truncated = out["raw_json"]["data_integrity"]["truncated_fields"]
    assert "message" in truncated


def test_normalizer_complete_structured_data_is_not_flagged():
    """A full structured process record stays 'complete' even when the
    message copy would be truncated."""
    out = Normalizer().normalize(
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4688,
            "timestamp": "2026-08-14T10:00:00+00:00",
            "user": "u",
            "message": "New Process Name:\tC:\\Windows\\Sys",
            "raw": {
                "record_number": 4,
                "NewProcessName": r"C:\Windows\System32\cmd.exe",
                "CommandLine": r"C:\Windows\System32\cmd.exe /c whoami",
            },
        }
    )
    assert out["data_integrity"] == "complete"
    assert out["raw_json"]["data_integrity"]["complete"] is True


def test_normalizer_non_process_event_not_flagged():
    out = Normalizer().normalize(logon_failure())
    assert out["data_integrity"] == "complete"


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


def test_brute_force_distributed_spray(db):
    from backend.detection.rules.brute_force import BruteForceRule

    records = [
        logon_failure(user="victim", source_ip=f"203.0.113.{i}") for i in range(1, 8)
    ]
    add_normalized(db, records)
    findings = BruteForceRule(db, threshold=5).evaluate(10)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "distinct source IPs" in findings[0].evidence
    assert len(findings[0].event_ids) == 7


def test_brute_force_moderate_spread(db):
    from backend.detection.rules.brute_force import BruteForceRule

    records = [
        logon_failure(user="victim", source_ip=f"192.168.1.{1 + i % 3}")
        for i in range(12)
    ]
    add_normalized(db, records)
    findings = BruteForceRule(db, threshold=5).evaluate(10)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "possible distributed brute force" in findings[0].evidence


def test_brute_force_no_spray_on_low_volume_spread(db):
    """9 failures across 3 IPs stay below threshold*2: no finding."""
    from backend.detection.rules.brute_force import BruteForceRule

    records = [
        logon_failure(user="victim", source_ip=f"192.168.1.{1 + i % 3}")
        for i in range(9)
    ]
    add_normalized(db, records)
    assert BruteForceRule(db, threshold=5).evaluate(10) == []


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
        db.add(
            NetworkConnection(
                pid=r["pid"],
                process=r["process"],
                local_ip=r["local_ip"],
                local_port=r["local_port"],
                remote_ip=r["remote_ip"],
                remote_port=r["remote_port"],
                state=r["state"],
                is_listening=r["is_listening"],
                observed_at=Normalizer._safe_ts(r["timestamp"]),
            )
        )
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
        db.add(
            NetworkConnection(
                pid=r["pid"],
                process=r["process"],
                local_ip=r["local_ip"],
                local_port=r["local_port"],
                remote_ip=r["remote_ip"],
                remote_port=r["remote_port"],
                state=r["state"],
                is_listening=r["is_listening"],
                observed_at=Normalizer._safe_ts(r["timestamp"]),
            )
        )
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
    from datetime import datetime

    from backend.database.models import FileScan
    from backend.detection.rules.malware_file import MalwareFileRule

    db.add(
        FileScan(
            file_path="C:\\Users\\Public\\beacon.exe",
            file_name="beacon.exe",
            sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            size=12345,
            signed=False,
            is_malicious=True,
            signature_name="known-bad-sample",
            scanned_at=datetime.now(UTC),
        )
    )
    db.commit()
    findings = MalwareFileRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1105"


def test_email_phishing_rule(db):
    from datetime import datetime

    from backend.database.models import EmailMessage
    from backend.detection.rules.email_phishing import EmailPhishingRule

    db.add(
        EmailMessage(
            sender="noreply@accounts-update.tk",
            recipient="alice@corp.local",
            subject="URGENT: verify your account password now",
            body="Click https://evil.tk/login to verify. Attachment: invoice.exe",
            attachment_types=".exe",
            ip_address="203.0.113.7",
            received_at=datetime.now(UTC),
        )
    )
    db.commit()
    findings = EmailPhishingRule(db, threshold=2.0).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1566"


def test_usb_device_rule(db):
    from datetime import datetime

    from backend.database.models import UsbDevice
    from backend.detection.rules.usb import UsbDeviceRule

    db.add(
        UsbDevice(
            device_name="Kingston DataTraveler",
            device_id="USB\\VID_0951&PID_1666",
            vendor="Kingston",
            serial="07018AC27C",
            inserted_at=datetime.now(UTC),
        )
    )
    db.commit()
    findings = UsbDeviceRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1091"


def test_dns_http_exfil_rule(db):
    from datetime import datetime

    from backend.database.models import DnsQuery, HttpRequest
    from backend.detection.rules.dns_http import DnsHttpExfilRule

    for q in dns_exfil_for_db():
        db.add(
            DnsQuery(
                process="svchost.exe",
                pid=500,
                query=q,
                response="8.8.4.4",
                response_size=600,
                observed_at=datetime.now(UTC),
            )
        )
    db.add(
        HttpRequest(
            process="powershell.exe",
            pid=1234,
            method="POST",
            url="https://evil.xyz/upload",
            host="evil.xyz",
            status_code=200,
            request_body_size=2_000_000,
            response_body_size=5_000_000,
            observed_at=datetime.now(UTC),
        )
    )
    db.commit()
    findings = DnsHttpExfilRule(db).evaluate(10)
    assert len(findings) >= 1
    assert all(f.mitre_id == "T1071" for f in findings)


def dns_exfil_for_db():
    return [f"data{i}.evil.xyz" for i in range(25)]


def test_kill_chain_correlation(db):
    from datetime import datetime

    from backend.database.models import Alert
    from backend.detection.rules.correlation import KillChainCorrelationRule

    for name, rule in (
        ("Brute Force Attack", "brute_force"),
        ("Persistence Mechanism Installed", "persistence"),
        ("Suspicious Privilege Escalation", "privilege_escalation"),
    ):
        db.add(
            Alert(
                name=name,
                rule=rule,
                status="open",
                severity="high",
                mitre_id="T1110",
                mitre_name="Brute Force",
                mitre_tactic="Credential Access",
                evidence="Brute force detected for account 'administrator' from 192.168.99.77.",
                created_at=datetime.now(UTC),
            )
        )
    db.commit()
    findings = KillChainCorrelationRule(db, threshold=2).evaluate(10)
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_kill_chain_timing_composition(db):
    """Timing-composed correlation: stages arriving in canonical order with
    an exfiltration terminal stage score a coherent critical chain."""
    from datetime import datetime, timedelta

    from backend.database.models import Alert
    from backend.detection.rules.correlation import KillChainCorrelationRule

    now = datetime.now(UTC)
    for name, rule, offset in (
        ("Network Service Discovery", "network_recon", 45),
        ("Brute Force Attack", "brute_force", 30),
        ("Data Staging", "data_staging", 12),
        ("Data Exfiltration", "dns_http_exfil", 3),
    ):
        db.add(
            Alert(
                name=name,
                rule=rule,
                status="open",
                severity="high",
                mitre_id="T1046",
                mitre_name="Discovery",
                mitre_tactic="Discovery",
                evidence="Brute force detected for account 'administrator' from 192.168.99.77.",
                created_at=now - timedelta(minutes=offset),
            )
        )
    db.commit()
    findings = KillChainCorrelationRule(db, threshold=2).evaluate(10)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "canonical kill-chain order" in findings[0].evidence
    assert "terminal stage" in findings[0].evidence
    assert findings[0].confidence >= 0.9


def test_kill_chain_timing_reversed_sequence(db):
    """Scrambled stage arrival (exfiltration before discovery) still fires
    on stage count but must report the ordering deviation and a softer
    confidence than a coherent chain."""
    from datetime import datetime, timedelta

    from backend.database.models import Alert
    from backend.detection.rules.correlation import KillChainCorrelationRule

    now = datetime.now(UTC)
    for name, rule, offset in (
        ("Data Exfiltration", "dns_http_exfil", 3),
        ("Network Service Discovery", "network_recon", 12),
    ):
        db.add(
            Alert(
                name=name,
                rule=rule,
                status="open",
                severity="high",
                mitre_id="T1048",
                mitre_name="Exfiltration",
                mitre_tactic="Exfiltration",
                evidence="from 192.168.99.77.",
                created_at=now - timedelta(minutes=offset),
            )
        )
    db.commit()
    findings = KillChainCorrelationRule(db, threshold=2, window_minutes=60).evaluate(10)
    assert len(findings) == 1
    assert "ordering deviates" in findings[0].evidence
    assert findings[0].confidence < 0.9


def test_kill_chain_covers_expanded_rule_families(db):
    """The kill-chain stage map must classify every native + expanded rule
    family so correlated alerts from the 52-rule expansion still build
    coherent chains instead of falling into 'Other'."""
    from datetime import datetime

    from backend.database.models import Alert
    from backend.detection.rules.correlation import (
        KILL_CHAIN_STAGES,
        KillChainCorrelationRule,
    )

    families = [
        "spearphishing_attachment",
        "wmi_execution",
        "startup_folder",
        "uac_bypass",
        "disable_defender",
        "lsass_dump",
        "account_discovery",
        "rdp_lateral",
        "archive_collection",
        "encrypted_channel",
    ]
    for rule in families:
        assert rule in KILL_CHAIN_STAGES, f"{rule} missing from stage map"
        assert KILL_CHAIN_STAGES[rule] != "Other"

    now = datetime.now(UTC)
    for rule in families:
        db.add(
            Alert(
                name=f"Expanded {rule}",
                rule=rule,
                status="open",
                severity="high",
                mitre_id="T1071",
                mitre_name="Expanded",
                mitre_tactic="Expanded",
                evidence="Brute force detected for account 'administrator' from 192.168.99.77.",
                created_at=now,
            )
        )
    db.commit()
    findings = KillChainCorrelationRule(db, threshold=2).evaluate(10)
    assert findings, "expanded families must produce a correlated chain"
    assert all("Other" not in f.evidence for f in findings)


def test_credential_access_lsass_dump(db):
    from backend.detection.rules.credential_access import CredentialAccessRule

    add_normalized(db, sysmon_lsass_dump() + sysmon_lsass_benign())
    findings = CredentialAccessRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1003.001"
    assert findings[0].severity == "critical"
    assert "lsass.exe" in findings[0].evidence


def test_registry_runkey_persistence(db):
    from backend.detection.rules.registry_runkey import RegistryRunKeyRule

    add_normalized(db, sysmon_runkey() + sysmon_benign_registry())
    findings = RegistryRunKeyRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1547.001"
    assert "\\Run\\" in findings[0].evidence


def test_scheduled_task_abuse(db):
    from backend.detection.rules.scheduled_task import ScheduledTaskAbuseRule

    add_normalized(db, benign_process() + schtasks_create())
    findings = ScheduledTaskAbuseRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1053.005"
    assert "SystemUpdater" in findings[0].evidence


def test_wmi_event_subscription(db):
    from backend.detection.rules.wmi_event_subscription import WmiEventSubscriptionRule

    add_normalized(db, wmi_subscription())
    findings = WmiEventSubscriptionRule(db).evaluate(10)
    assert len(findings) >= 2
    assert all(f.mitre_id == "T1546.003" for f in findings)
    assert all(f.severity == "critical" for f in findings)


def test_account_tampering(db):
    from backend.detection.rules.account_tampering import AccountTamperingRule

    add_normalized(db, admin_tampering())
    findings = AccountTamperingRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1098" for f in findings)


def test_masquerading_system_binary(db):
    from backend.detection.rules.masquerading import MasqueradingRule

    add_normalized(db, benign_process() + masquerading_process())
    findings = MasqueradingRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1036"
    assert "svchost.exe" in findings[0].evidence


def test_hidden_artifacts(db):
    from backend.detection.rules.hidden_artifacts import HiddenArtifactsRule

    add_normalized(db, hidden_artifact())
    findings = HiddenArtifactsRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1564" for f in findings)


def test_hidden_artifacts_uvicorn_module_syntax_not_flagged(db):
    from backend.detection.rules.hidden_artifacts import HiddenArtifactsRule

    def _proc(name, cmdline, pid):
        return {
            "source": "process",
            "pid": pid,
            "ppid": 900,
            "name": name,
            "path": f"C:\\Windows\\System32\\{name}",
            "cmdline": cmdline,
            "raw": {"cmdline": cmdline},
            "parent_name": "explorer.exe",
            "user": "HAARAPHEL\\Haaraphel",
            "is_new": True,
            "timestamp": "2026-08-07T21:00:00Z",
        }

    add_normalized(
        db,
        [
            _proc(
                "python.exe",
                "F:\\My Project\\BARAQ\\venv\\Scripts\\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000",
                25956,
            ),
            _proc("gunicorn.exe", "gunicorn myapp.wsgi:application -w 2", 25957),
        ],
    )
    assert HiddenArtifactsRule(db).evaluate(10) == []


def test_lolbin_execution(db):
    from backend.detection.rules.lolbin_execution import LolBinExecutionRule

    add_normalized(db, benign_process() + lolbin_usage())
    findings = LolBinExecutionRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1218" for f in findings)
    assert any("rundll32" in f.evidence for f in findings)
    assert any("certutil" in f.evidence for f in findings)


def test_exfiltration_volume(db):
    from backend.detection.rules.exfiltration_volume import ExfiltrationVolumeRule

    add_normalized(db, http_volume())
    findings = ExfiltrationVolumeRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1041"
    assert "powershell.exe" in findings[0].evidence


def test_log_clearing(db):
    from backend.detection.rules.log_clearing import LogClearingRule

    add_normalized(db, log_clear())
    findings = LogClearingRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1070.001" for f in findings)


def test_ransomware_impact(db):
    from backend.detection.rules.impact import RansomwareImpactRule

    add_normalized(db, ransomware_impact())
    findings = RansomwareImpactRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1486" for f in findings)
    assert all(f.severity == "critical" for f in findings)
    assert any("ransomware-style file extensions" in f.evidence for f in findings)
    assert any("ransom-note" in f.evidence for f in findings)


def test_inhibit_recovery(db):
    from backend.detection.rules.impact import InhibitRecoveryRule

    add_normalized(db, recovery_inhibit())
    findings = InhibitRecoveryRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1490" for f in findings)
    assert all(f.severity == "critical" for f in findings)
    assert any("vssadmin" in f.evidence for f in findings)


def test_credential_store_theft(db):
    from backend.detection.rules.credential_store import CredentialStoreTheftRule

    add_normalized(db, credential_store_theft())
    findings = CredentialStoreTheftRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1555" for f in findings)
    assert any("cmdkey" in f.evidence for f in findings)
    assert any("Login Data" in f.evidence for f in findings)


def test_bits_job(db):
    from backend.detection.rules.bits_jobs import BitsJobRule

    add_normalized(db, bits_download())
    findings = BitsJobRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1197"
    assert "user-writable/temp" in findings[0].evidence


def test_shortcut_modification(db):
    from backend.detection.rules.shortcut_modification import ShortcutModificationRule

    add_normalized(db, shortcut_persistence())
    findings = ShortcutModificationRule(db).evaluate(10)
    assert len(findings) == 1
    assert findings[0].mitre_id == "T1547.009"
    assert "Startup" in findings[0].evidence


def test_new_rules_no_false_positives_on_benign(db):
    from backend.detection.rules.bits_jobs import BitsJobRule
    from backend.detection.rules.credential_access import CredentialAccessRule
    from backend.detection.rules.credential_store import CredentialStoreTheftRule
    from backend.detection.rules.exfiltration_volume import ExfiltrationVolumeRule
    from backend.detection.rules.hidden_artifacts import HiddenArtifactsRule
    from backend.detection.rules.impact import InhibitRecoveryRule, RansomwareImpactRule
    from backend.detection.rules.log_clearing import LogClearingRule
    from backend.detection.rules.lolbin_execution import LolBinExecutionRule
    from backend.detection.rules.masquerading import MasqueradingRule
    from backend.detection.rules.registry_runkey import RegistryRunKeyRule
    from backend.detection.rules.scheduled_task import ScheduledTaskAbuseRule
    from backend.detection.rules.shortcut_modification import ShortcutModificationRule
    from backend.detection.rules.wmi_event_subscription import WmiEventSubscriptionRule

    add_normalized(db, benign_baseline(60) + benign_process())
    assert CredentialAccessRule(db).evaluate(10) == []
    assert RegistryRunKeyRule(db).evaluate(10) == []
    assert ScheduledTaskAbuseRule(db).evaluate(10) == []
    assert WmiEventSubscriptionRule(db).evaluate(10) == []
    assert MasqueradingRule(db).evaluate(10) == []
    assert HiddenArtifactsRule(db).evaluate(10) == []
    assert LolBinExecutionRule(db).evaluate(10) == []
    assert ExfiltrationVolumeRule(db).evaluate(10) == []
    assert LogClearingRule(db).evaluate(10) == []
    assert RansomwareImpactRule(db).evaluate(10) == []
    assert InhibitRecoveryRule(db).evaluate(10) == []
    assert CredentialStoreTheftRule(db).evaluate(10) == []
    assert BitsJobRule(db).evaluate(10) == []
    assert ShortcutModificationRule(db).evaluate(10) == []


def _seed_org_events(db, org: str, attempts: int = 12) -> None:
    from backend.analyzers.normalizer import Normalizer

    normalizer = Normalizer()
    for record in brute_force(attempts=attempts):
        db.add(NormalizedEvent(**normalizer.normalize(record), org=org))
    db.commit()


def test_brute_force_rule_is_scoped_to_org(db):
    """Regression: a rule must only evaluate events from its own org."""
    from backend.detection.rules.brute_force import BruteForceRule

    _seed_org_events(db, "univ-a")
    _seed_org_events(db, "univ-b")

    rule_a = BruteForceRule(db, threshold=5)
    rule_a.org = "univ-a"
    findings_a = rule_a.evaluate(10)
    assert len(findings_a) == 1
    assert len(findings_a[0].event_ids) == 12

    rule_b = BruteForceRule(db, threshold=5)
    rule_b.org = "univ-b"
    findings_b = rule_b.evaluate(10)
    assert len(findings_b) == 1
    assert len(findings_b[0].event_ids) == 12

    rule_c = BruteForceRule(db, threshold=5)
    rule_c.org = "univ-c"
    assert rule_c.evaluate(10) == []

    rule_admin = BruteForceRule(db, threshold=5)
    admin_findings = rule_admin.evaluate(10)
    assert sum(len(f.event_ids) for f in admin_findings) == 24


def test_rule_engine_isolates_orgs_and_admin_sees_all(db):
    """Full engine run: findings from one org never leak into another org's."""
    from sqlalchemy import select

    from backend.detection.rules_engine import RulesEngine

    _seed_org_events(db, "univ-a")
    _seed_org_events(db, "univ-b")

    engine_a = RulesEngine(db, org="univ-a")
    engine_b = RulesEngine(db, org="univ-b")

    ids_a = {eid for f in engine_a.run(10) for eid in f.event_ids}
    ids_b = {eid for f in engine_b.run(10) for eid in f.event_ids}
    assert ids_a and ids_b
    assert ids_a.isdisjoint(ids_b)

    all_ids = set(
        db.scalars(
            select(NormalizedEvent.id).where(NormalizedEvent.org == "univ-a")
        ).all()
    )
    assert ids_a <= all_ids

    admin_engine = RulesEngine(db)
    admin_ids = {eid for f in admin_engine.run(10) for eid in f.event_ids}
    assert ids_a | ids_b == admin_ids
