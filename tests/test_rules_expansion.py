"""Tests for the 52-rule native expansion (initial access, execution,
persistence, privilege escalation, defense evasion, credential access,
discovery, lateral movement, collection, C2 / exfiltration)."""

from __future__ import annotations

import pytest

from backend.detection.rules.c2_exfil_extra import (
    EncryptedChannelRule,
    ExfilAlternativeProtocolRule,
    ExfilWebServiceRule,
    ProxyToolRule,
    UnusualPortRule,
)
from backend.detection.rules.collection import (
    ArchiveCollectionRule,
    ClipboardCaptureRule,
    LocalDataCollectionRule,
    ScreenCaptureRule,
)
from backend.detection.rules.credential_access_extra import (
    CachedCredentialsRule,
    KeyloggingRule,
    LsassDumpRule,
    NetworkSniffingRule,
    NtdsDumpRule,
    PasswordStoreTheftRule,
)
from backend.detection.rules.defense_evasion_extra import (
    DisableAuditRule,
    DisableDefenderRule,
    DisableFirewallRule,
    DisableSystemRestoreRule,
    HiddenFileAttributeRule,
)
from backend.detection.rules.discovery import (
    AccountDiscoveryRule,
    DomainDiscoveryRule,
    FileSystemDiscoveryRule,
    SecuritySoftwareDiscoveryRule,
    ShareDiscoveryRule,
    SystemInfoDiscoveryRule,
)
from backend.detection.rules.execution import (
    AtJobRule,
    CmdScriptExecutionRule,
    MsBuildExecutionRule,
    PythonExecutionRule,
    ServiceExecutionRule,
    WmiExecutionRule,
)
from backend.detection.rules.initial_access import (
    DriveByCompromiseRule,
    ExternalServiceExploitRule,
    SpearphishingAttachmentRule,
    SpearphishingLinkRule,
)
from backend.detection.rules.lateral_movement_extra import (
    RdpLateralRule,
    SmbAdminShareRule,
    SshLateralRule,
    WinRmLateralRule,
)
from backend.detection.rules.persistence_extra import (
    AccessibilityFeatureRule,
    AppInitDllRule,
    IfeoDebuggerRule,
    LogonScriptRule,
    NetshHelperRule,
    ServiceImagePathPersistenceRule,
    StartupFolderRule,
)
from backend.detection.rules.privilege_escalation_extra import (
    AlwaysInstallElevatedRule,
    NamedPipeImpersonationRule,
    SeDebugPrivilegeRule,
    UacBypassRule,
    UnquotedServicePathRule,
)
from tests.fixtures import (
    accessibility_feature,
    account_discovery,
    add_normalized,
    always_install_elevated,
    appinit_dlls,
    archive_collection,
    at_job,
    benign_baseline,
    cached_credentials,
    clipboard_capture,
    cmd_script_execution,
    disable_audit,
    disable_defender,
    disable_firewall,
    disable_system_restore,
    domain_discovery,
    drive_by,
    encrypted_channel,
    exfil_alt,
    exfil_web,
    external_service_exploit,
    filesystem_discovery,
    hidden_file_attribute,
    ifeo_debugger,
    keylogging,
    local_data,
    logon_script,
    lsass_dump,
    msbuild_execution,
    named_pipe,
    netsh_helper,
    ntds_dump,
    password_store,
    proxy_tool,
    python_execution,
    rdp_lateral,
    screen_capture,
    se_debug_privilege,
    security_software,
    service_execution,
    service_image_path,
    share_discovery,
    smb_admin_share,
    sniffing,
    spearphishing_attachment,
    spearphishing_link,
    ssh_lateral,
    startup_folder,
    system_info,
    uac_bypass,
    unquoted_service_path,
    unusual_port,
    winrm_lateral,
    wmi_execution,
)

NEW_RULES = [
    (SpearphishingAttachmentRule, "spearphishing_attachment", "T1566.001"),
    (SpearphishingLinkRule, "spearphishing_link", "T1566.002"),
    (DriveByCompromiseRule, "drive_by_compromise", "T1189"),
    (ExternalServiceExploitRule, "external_service_exploit", "T1190"),
    (CmdScriptExecutionRule, "cmd_script_execution", "T1059.003"),
    (WmiExecutionRule, "wmi_execution", "T1047"),
    (AtJobRule, "at_job", "T1053.002"),
    (ServiceExecutionRule, "service_execution", "T1569.002"),
    (MsBuildExecutionRule, "msbuild_execution", "T1127.001"),
    (PythonExecutionRule, "python_execution", "T1059.006"),
    (StartupFolderRule, "startup_folder", "T1547.001"),
    (ServiceImagePathPersistenceRule, "service_image_path_persistence", "T1543.003"),
    (AppInitDllRule, "appinit_dlls", "T1546.010"),
    (AccessibilityFeatureRule, "accessibility_feature", "T1546.008"),
    (IfeoDebuggerRule, "ifeo_debugger", "T1546.012"),
    (NetshHelperRule, "netsh_helper", "T1546.007"),
    (LogonScriptRule, "logon_script", "T1037.001"),
    (UacBypassRule, "uac_bypass", "T1548.002"),
    (SeDebugPrivilegeRule, "se_debug_privilege", "T1134.001"),
    (NamedPipeImpersonationRule, "named_pipe_impersonation", "T1134.005"),
    (UnquotedServicePathRule, "unquoted_service_path", "T1574.009"),
    (AlwaysInstallElevatedRule, "always_install_elevated", "T1574.005"),
    (DisableDefenderRule, "disable_defender", "T1562.001"),
    (DisableFirewallRule, "disable_firewall", "T1562.004"),
    (DisableAuditRule, "disable_audit", "T1562.002"),
    (HiddenFileAttributeRule, "hidden_file_attribute", "T1564.001"),
    (DisableSystemRestoreRule, "disable_system_restore", "T1562.001"),
    (LsassDumpRule, "lsass_dump", "T1003.001"),
    (NtdsDumpRule, "ntds_dump", "T1003.003"),
    (PasswordStoreTheftRule, "password_store_theft", "T1555"),
    (KeyloggingRule, "keylogging", "T1056.001"),
    (NetworkSniffingRule, "network_sniffing", "T1040"),
    (CachedCredentialsRule, "cached_credentials", "T1003.005"),
    (AccountDiscoveryRule, "account_discovery", "T1087"),
    (ShareDiscoveryRule, "share_discovery", "T1135"),
    (SystemInfoDiscoveryRule, "system_info_discovery", "T1082"),
    (DomainDiscoveryRule, "domain_discovery", "T1482"),
    (SecuritySoftwareDiscoveryRule, "security_software_discovery", "T1518.001"),
    (FileSystemDiscoveryRule, "filesystem_discovery", "T1083"),
    (SmbAdminShareRule, "smb_admin_share", "T1021.002"),
    (RdpLateralRule, "rdp_lateral", "T1021.001"),
    (WinRmLateralRule, "winrm_lateral", "T1021.006"),
    (SshLateralRule, "ssh_lateral", "T1021.004"),
    (ClipboardCaptureRule, "clipboard_capture", "T1115"),
    (ScreenCaptureRule, "screen_capture", "T1113"),
    (ArchiveCollectionRule, "archive_collection", "T1560.001"),
    (LocalDataCollectionRule, "local_data_collection", "T1005"),
    (ProxyToolRule, "proxy_tool", "T1090"),
    (UnusualPortRule, "unusual_port", "T1571"),
    (EncryptedChannelRule, "encrypted_channel", "T1573"),
    (ExfilAlternativeProtocolRule, "exfil_alternative_protocol", "T1048.003"),
    (ExfilWebServiceRule, "exfil_web_service", "T1567"),
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


def test_rules_engine_has_100_native_rules(db):
    from backend.detection.rules_engine import build_rules

    rules = build_rules(db)
    native = [
        r
        for r in rules
        if getattr(r, "rule_id", "") != ""
        and type(r).__module__.startswith("backend.detection.rules")
    ]
    assert len(native) >= 100


@pytest.mark.parametrize(
    "rule_cls,fixture",
    [
        (SpearphishingAttachmentRule, spearphishing_attachment),
        (SpearphishingLinkRule, spearphishing_link),
        (DriveByCompromiseRule, drive_by),
        (ExternalServiceExploitRule, external_service_exploit),
        (CmdScriptExecutionRule, cmd_script_execution),
        (WmiExecutionRule, wmi_execution),
        (AtJobRule, at_job),
        (ServiceExecutionRule, service_execution),
        (MsBuildExecutionRule, msbuild_execution),
        (PythonExecutionRule, python_execution),
        (StartupFolderRule, startup_folder),
        (ServiceImagePathPersistenceRule, service_image_path),
        (AppInitDllRule, appinit_dlls),
        (AccessibilityFeatureRule, accessibility_feature),
        (IfeoDebuggerRule, ifeo_debugger),
        (NetshHelperRule, netsh_helper),
        (LogonScriptRule, logon_script),
        (UacBypassRule, uac_bypass),
        (SeDebugPrivilegeRule, se_debug_privilege),
        (NamedPipeImpersonationRule, named_pipe),
        (UnquotedServicePathRule, unquoted_service_path),
        (AlwaysInstallElevatedRule, always_install_elevated),
        (DisableDefenderRule, disable_defender),
        (DisableFirewallRule, disable_firewall),
        (DisableAuditRule, disable_audit),
        (HiddenFileAttributeRule, hidden_file_attribute),
        (DisableSystemRestoreRule, disable_system_restore),
        (LsassDumpRule, lsass_dump),
        (NtdsDumpRule, ntds_dump),
        (PasswordStoreTheftRule, password_store),
        (KeyloggingRule, keylogging),
        (NetworkSniffingRule, sniffing),
        (CachedCredentialsRule, cached_credentials),
        (AccountDiscoveryRule, account_discovery),
        (ShareDiscoveryRule, share_discovery),
        (SystemInfoDiscoveryRule, system_info),
        (DomainDiscoveryRule, domain_discovery),
        (SecuritySoftwareDiscoveryRule, security_software),
        (FileSystemDiscoveryRule, filesystem_discovery),
        (SmbAdminShareRule, smb_admin_share),
        (RdpLateralRule, rdp_lateral),
        (WinRmLateralRule, winrm_lateral),
        (SshLateralRule, ssh_lateral),
        (ClipboardCaptureRule, clipboard_capture),
        (ScreenCaptureRule, screen_capture),
        (ArchiveCollectionRule, archive_collection),
        (LocalDataCollectionRule, local_data),
        (ProxyToolRule, proxy_tool),
        (UnusualPortRule, unusual_port),
        (EncryptedChannelRule, encrypted_channel),
        (ExfilAlternativeProtocolRule, exfil_alt),
        (ExfilWebServiceRule, exfil_web),
    ],
    ids=[
        f.__name__
        for _, f in [
            (SpearphishingAttachmentRule, spearphishing_attachment),
            (SpearphishingLinkRule, spearphishing_link),
            (DriveByCompromiseRule, drive_by),
            (ExternalServiceExploitRule, external_service_exploit),
            (CmdScriptExecutionRule, cmd_script_execution),
            (WmiExecutionRule, wmi_execution),
            (AtJobRule, at_job),
            (ServiceExecutionRule, service_execution),
            (MsBuildExecutionRule, msbuild_execution),
            (PythonExecutionRule, python_execution),
            (StartupFolderRule, startup_folder),
            (ServiceImagePathPersistenceRule, service_image_path),
            (AppInitDllRule, appinit_dlls),
            (AccessibilityFeatureRule, accessibility_feature),
            (IfeoDebuggerRule, ifeo_debugger),
            (NetshHelperRule, netsh_helper),
            (LogonScriptRule, logon_script),
            (UacBypassRule, uac_bypass),
            (SeDebugPrivilegeRule, se_debug_privilege),
            (NamedPipeImpersonationRule, named_pipe),
            (UnquotedServicePathRule, unquoted_service_path),
            (AlwaysInstallElevatedRule, always_install_elevated),
            (DisableDefenderRule, disable_defender),
            (DisableFirewallRule, disable_firewall),
            (DisableAuditRule, disable_audit),
            (HiddenFileAttributeRule, hidden_file_attribute),
            (DisableSystemRestoreRule, disable_system_restore),
            (LsassDumpRule, lsass_dump),
            (NtdsDumpRule, ntds_dump),
            (PasswordStoreTheftRule, password_store),
            (KeyloggingRule, keylogging),
            (NetworkSniffingRule, sniffing),
            (CachedCredentialsRule, cached_credentials),
            (AccountDiscoveryRule, account_discovery),
            (ShareDiscoveryRule, share_discovery),
            (SystemInfoDiscoveryRule, system_info),
            (DomainDiscoveryRule, domain_discovery),
            (SecuritySoftwareDiscoveryRule, security_software),
            (FileSystemDiscoveryRule, filesystem_discovery),
            (SmbAdminShareRule, smb_admin_share),
            (RdpLateralRule, rdp_lateral),
            (WinRmLateralRule, winrm_lateral),
            (SshLateralRule, ssh_lateral),
            (ClipboardCaptureRule, clipboard_capture),
            (ScreenCaptureRule, screen_capture),
            (ArchiveCollectionRule, archive_collection),
            (LocalDataCollectionRule, local_data),
            (ProxyToolRule, proxy_tool),
            (UnusualPortRule, unusual_port),
            (EncryptedChannelRule, encrypted_channel),
            (ExfilAlternativeProtocolRule, exfil_alt),
            (ExfilWebServiceRule, exfil_web),
        ]
    ],
)
def test_new_rule_detects_fixture(db, rule_cls, fixture):
    findings = _findings(rule_cls, db, fixture())
    assert len(findings) >= 1, f"{rule_cls.rule_id} did not fire on its fixture"


def test_new_rules_silent_on_benign_baseline(db):
    add_normalized(db, benign_baseline())
    for rule_cls, _, _ in NEW_RULES:
        findings = rule_cls(db).evaluate(10)
        assert findings == [], f"{rule_cls.rule_id} fired on benign baseline"


def test_spearphishing_attachment_evidence(db):
    findings = _findings(SpearphishingAttachmentRule, db, spearphishing_attachment())
    assert ".docm" in findings[0].evidence


def test_rdp_lateral_requires_type_10(db):
    from tests.fixtures import _eventlog

    add_normalized(db, [_eventlog(4624, "logon", {"logon_type": 2})])
    assert RdpLateralRule(db).evaluate(10) == []
    add_normalized(db, [_eventlog(4624, "logon", {"logon_type": 10})])
    assert len(RdpLateralRule(db).evaluate(10)) == 1


def test_python_execution_ignores_system_path(db):
    from tests.fixtures import _process

    add_normalized(db, [_process("python.exe", r"C:\Python39\python.exe script.py")])
    assert PythonExecutionRule(db).evaluate(10) == []


def test_per_rule_overrides_disable_and_retune(monkeypatch, db):
    """BARAQ_RULE_OVERRIDES disables rules and adjusts severity/confidence
    without touching rule code (roadmap 3.1)."""
    import backend.detection.rules_engine as engine_mod

    monkeypatch.setattr(
        engine_mod,
        "RULE_OVERRIDES",
        {
            "usb_device": {"enabled": False},
            "brute_force": {"severity": "critical", "confidence": 0.95},
        },
    )
    rules = engine_mod.build_rules(db)
    by_id = {r.rule_id: r for r in rules}
    assert "usb_device" not in by_id, "disabled rule still registered"
    assert "brute_force" in by_id
    assert by_id["brute_force"].severity == "critical"
    assert by_id["brute_force"].confidence == 0.95
    assert by_id["brute_force"].rule_id == "brute_force"


def test_rule_override_ignores_unknown_ids(monkeypatch, db):
    import backend.detection.rules_engine as engine_mod

    monkeypatch.setattr(
        engine_mod, "RULE_OVERRIDES", {"no_such_rule_xyz": {"enabled": False}}
    )
    rules = engine_mod.build_rules(db)
    assert len(rules) >= 100, "unknown override ids must be ignored"
