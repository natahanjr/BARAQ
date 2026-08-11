"""Tests for the AD / process-abuse / defense-evasion / exfil-C2 rule set
(19 rules added for the enterprise-detection expansion)."""
from __future__ import annotations

import pytest

from backend.detection.rules.kerberos import (
    AsRepRoastingRule,
    DCSyncRule,
    GoldenTicketRule,
    KerberoastingRule,
    PassTheHashRule,
    PassTheTicketRule,
    SilverTicketRule,
)
from backend.detection.rules.ad_abuse import BloodHoundReconRule, GpoAbuseRule
from backend.detection.rules.process_abuse import (
    DllSideloadingRule,
    PrintNightmareRule,
    ProcessInjectionRule,
    TokenManipulationRule,
)
from backend.detection.rules.defense_evasion import (
    AmsiBypassRule,
    CertificateSpoofingRule,
    SafeBootTamperingRule,
)
from backend.detection.rules.exfil_c2 import (
    CloudSyncExfilRule,
    DnsTunnelingRule,
    WebhookC2Rule,
)
from tests.fixtures import (
    add_normalized,
    amsi_bypass,
    asrep_roast,
    benign_baseline,
    bloodhound_recon,
    cert_spoof,
    cloud_sync_exfil,
    dcsync,
    dll_sideload,
    dns_tunnel,
    golden_ticket,
    gpo_abuse,
    kerberoast,
    pass_the_hash,
    pass_the_ticket,
    printnightmare,
    process_inject,
    safeboot_tamper,
    silver_ticket,
    token_manip,
    webhook_c2,
)

NEW_RULES = [
    (KerberoastingRule, "kerberoasting", "T1558.003"),
    (AsRepRoastingRule, "as_rep_roasting", "T1558.004"),
    (DCSyncRule, "dcsync", "T1003.006"),
    (GoldenTicketRule, "golden_ticket", "T1558.001"),
    (SilverTicketRule, "silver_ticket", "T1558.002"),
    (PassTheHashRule, "pass_the_hash", "T1550.002"),
    (PassTheTicketRule, "pass_the_ticket", "T1550.003"),
    (BloodHoundReconRule, "bloodhound_recon", "T1087"),
    (GpoAbuseRule, "gpo_abuse", "T1484.001"),
    (DllSideloadingRule, "dll_sideloading", "T1574.002"),
    (ProcessInjectionRule, "process_injection", "T1055"),
    (TokenManipulationRule, "token_manipulation", "T1134"),
    (PrintNightmareRule, "printer_spooler_abuse", "T1068"),
    (SafeBootTamperingRule, "safeboot_tampering", "T1562.001"),
    (AmsiBypassRule, "amsi_bypass", "T1562.001"),
    (CertificateSpoofingRule, "certificate_spoofing", "T1553.004"),
    (CloudSyncExfilRule, "cloud_sync_exfil", "T1567.002"),
    (WebhookC2Rule, "webhook_c2", "T1102.001"),
    (DnsTunnelingRule, "dns_tunneling", "T1071.004"),
]


def _findings(rule_cls, db, records):
    add_normalized(db, records)
    return rule_cls(db).evaluate(10)


@pytest.mark.parametrize(
    "rule_cls,rule_id,mitre_id",
    NEW_RULES,
    ids=[r[1] for r in NEW_RULES],
)
def test_new_rules_register_with_mitre(db, rule_cls, rule_id, mitre_id):
    from backend.mitre.attack import TECHNIQUES

    rule = rule_cls(db)
    assert rule.rule_id == rule_id
    assert rule.mitre_id == mitre_id
    assert mitre_id in TECHNIQUES


def test_kerberoasting_event_and_tooling(db):
    from tests.fixtures import _process

    add_normalized(db, kerberoast())
    add_normalized(db, [_process("Rubeus.exe", "Rubeus.exe kerberoast /outfile:hashes.txt", path=r"C:\Tools\Rubeus.exe")])
    findings = KerberoastingRule(db).evaluate(10)
    assert len(findings) == 2
    assert all(f.mitre_id == "T1558.003" for f in findings)


def test_kerberoasting_skips_machine_accounts(db):
    findings = _findings(KerberoastingRule, db, kerberoast(user="dc01$"))
    assert findings == []


def test_as_rep_roasting(db):
    findings = _findings(AsRepRoastingRule, db, asrep_roast())
    assert len(findings) == 1
    assert "pre-authentication" in findings[0].evidence


def test_dcsync(db):
    findings = _findings(DCSyncRule, db, dcsync())
    assert len(findings) == 1
    assert findings[0].evidence.startswith("Account 'mallory'")


def test_dcsync_skips_dc_accounts(db):
    assert not _findings(DCSyncRule, db, dcsync(user="dc01$"))


def test_golden_ticket(db):
    findings = _findings(GoldenTicketRule, db, golden_ticket())
    assert len(findings) == 1
    assert "krbtgt" in findings[0].evidence


def test_silver_ticket(db):
    findings = _findings(SilverTicketRule, db, silver_ticket())
    assert len(findings) == 1
    assert "privileged account" in findings[0].evidence


def test_pass_the_hash(db):
    findings = _findings(PassTheHashRule, db, pass_the_hash())
    assert len(findings) == 1
    assert "NTLM" in findings[0].evidence


def test_pass_the_ticket(db):
    findings = _findings(PassTheTicketRule, db, pass_the_ticket())
    assert len(findings) == 1
    assert "Kerberos" in findings[0].evidence


def test_bloodhound_recon(db):
    findings = _findings(BloodHoundReconRule, db, bloodhound_recon())
    assert len(findings) == 1
    assert "CollectionMethod" in findings[0].evidence


def test_gpo_abuse_event(db):
    findings = _findings(GpoAbuseRule, db, gpo_abuse())
    assert len(findings) == 1
    assert "CN=Policies" in findings[0].evidence


def test_dll_sideloading(db):
    findings = _findings(DllSideloadingRule, db, dll_sideload())
    assert len(findings) == 1
    assert "side-loading" in findings[0].evidence


def test_dll_sideloading_system32_module_ignored(db):
    assert not _findings(
        DllSideloadingRule,
        db,
        dll_sideload(module=r"C:\Windows\System32\kernel32.dll"),
    )


def test_process_injection(db):
    findings = _findings(ProcessInjectionRule, db, process_inject())
    assert len(findings) == 1
    assert "CreateRemoteThread" in findings[0].evidence


def test_token_manipulation(db):
    findings = _findings(TokenManipulationRule, db, token_manip())
    assert len(findings) == 1
    assert "token::elevate" in findings[0].evidence


def test_printnightmare(db):
    findings = _findings(PrintNightmareRule, db, printnightmare())
    assert len(findings) == 1
    assert "PrintUIEntry" in findings[0].evidence


def test_safeboot_tampering(db):
    findings = _findings(SafeBootTamperingRule, db, safeboot_tamper())
    assert len(findings) == 1
    assert "safeboot" in findings[0].evidence


def test_amsi_bypass(db):
    findings = _findings(AmsiBypassRule, db, amsi_bypass())
    assert len(findings) == 1
    assert "amsiInitFailed" in findings[0].evidence


def test_certificate_spoofing(db):
    findings = _findings(CertificateSpoofingRule, db, cert_spoof())
    assert len(findings) == 1
    assert "certutil" in findings[0].evidence


def test_cloud_sync_exfil(db):
    findings = _findings(CloudSyncExfilRule, db, cloud_sync_exfil())
    assert len(findings) == 1
    assert "rclone" in findings[0].evidence


def test_webhook_c2(db):
    findings = _findings(WebhookC2Rule, db, webhook_c2())
    assert len(findings) >= 2
    assert all(f.mitre_id == "T1102.001" for f in findings)


def test_dns_tunneling(db):
    findings = _findings(DnsTunnelingRule, db, dns_tunnel())
    assert len(findings) >= 2
    assert any("long labels" in f.evidence for f in findings)
    assert any("tunneling volume" in f.evidence for f in findings)


def test_new_rules_silent_on_benign_baseline(db):
    add_normalized(db, benign_baseline())
    for rule_cls, _, _ in NEW_RULES:
        findings = rule_cls(db).evaluate(10)
        assert findings == [], f"{rule_cls.rule_id} fired on benign baseline"
