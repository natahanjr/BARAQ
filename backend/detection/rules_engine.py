"""Rules engine - orchestrates all detection rules.

Runs each enabled rule against the current event corpus and routes
findings to the alerting service (persistence + MITRE enrichment).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from backend.detection.rules.base import BaseRule, DetectionResult
from backend.detection.rules.brute_force import BruteForceRule
from backend.detection.rules.network_recon import NetworkReconRule
from backend.detection.rules.persistence import PersistenceRule
from backend.detection.rules.powershell import SuspiciousPowerShellRule
from backend.detection.rules.privilege_escalation import PrivilegeEscalationRule
from backend.detection.rules.lateral_movement import LateralMovementRule
from backend.detection.rules.data_staging import DataStagingRule
from backend.detection.rules.malware_file import MalwareFileRule
from backend.detection.rules.email_phishing import EmailPhishingRule
from backend.detection.rules.dns_http import DnsHttpExfilRule
from backend.detection.rules.usb import UsbDeviceRule
from backend.detection.rules.correlation import KillChainCorrelationRule
from backend.detection.rules.vulnerability import VulnerabilityRule
from backend.detection.rules.credential_access import CredentialAccessRule
from backend.detection.rules.registry_runkey import RegistryRunKeyRule
from backend.detection.rules.scheduled_task import ScheduledTaskAbuseRule
from backend.detection.rules.wmi_event_subscription import WmiEventSubscriptionRule
from backend.detection.rules.account_tampering import AccountTamperingRule
from backend.detection.rules.masquerading import MasqueradingRule
from backend.detection.rules.hidden_artifacts import HiddenArtifactsRule
from backend.detection.rules.lolbin_execution import LolBinExecutionRule
from backend.detection.rules.exfiltration_volume import ExfiltrationVolumeRule
from backend.detection.rules.log_clearing import LogClearingRule
from backend.detection.rules.c2_beacon import C2BeaconRule
from backend.detection.rules.impact import InhibitRecoveryRule, RansomwareImpactRule
from backend.detection.rules.credential_store import CredentialStoreTheftRule
from backend.detection.rules.bits_jobs import BitsJobRule
from backend.detection.rules.shortcut_modification import ShortcutModificationRule
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
from backend.detection.rules.initial_access import (
    DriveByCompromiseRule,
    ExternalServiceExploitRule,
    SpearphishingAttachmentRule,
    SpearphishingLinkRule,
)
from backend.detection.rules.execution import (
    AtJobRule,
    CmdScriptExecutionRule,
    MsBuildExecutionRule,
    PythonExecutionRule,
    ServiceExecutionRule,
    WmiExecutionRule,
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
from backend.detection.rules.defense_evasion_extra import (
    DisableAuditRule,
    DisableDefenderRule,
    DisableFirewallRule,
    DisableSystemRestoreRule,
    HiddenFileAttributeRule,
)
from backend.detection.rules.credential_access_extra import (
    CachedCredentialsRule,
    KeyloggingRule,
    LsassDumpRule,
    NetworkSniffingRule,
    NtdsDumpRule,
    PasswordStoreTheftRule,
)
from backend.detection.rules.discovery import (
    AccountDiscoveryRule,
    DomainDiscoveryRule,
    FileSystemDiscoveryRule,
    SecuritySoftwareDiscoveryRule,
    ShareDiscoveryRule,
    SystemInfoDiscoveryRule,
)
from backend.detection.rules.lateral_movement_extra import (
    RdpLateralRule,
    SmbAdminShareRule,
    SshLateralRule,
    WinRmLateralRule,
)
from backend.detection.rules.collection import (
    ArchiveCollectionRule,
    ClipboardCaptureRule,
    LocalDataCollectionRule,
    ScreenCaptureRule,
)
from backend.detection.rules.c2_exfil_extra import (
    EncryptedChannelRule,
    ExfilAlternativeProtocolRule,
    ExfilWebServiceRule,
    ProxyToolRule,
    UnusualPortRule,
)
from backend.detection.sigma.engine import SigmaRuleEngine
from backend.detection.correlation_engine import CorrelationEngine
from backend.config import (
    KILL_CHAIN,
    PORT_SCAN_DISTINCT_PORTS,
    PORT_SCAN_WINDOW_SECONDS,
    RULES_COUNT,
    RULE_OVERRIDES,
)
from backend.mitre.attack import get_recommendation, get_tactic, get_technique_name

logger = logging.getLogger("baraq.detection")


def build_rules(session: Session, overrides: dict | None = None) -> list[BaseRule]:
    """Instantiate all detection rules (the platform's rule set).

    ``overrides`` maps rule_id -> constructor kwargs (used by the parameter
    tuning script to grid-search thresholds without touching the defaults).
    """
    overrides = overrides or {}

    def build(cls, rule_id: str, *args, **kwargs):
        kwargs.update(overrides.get(rule_id, {}))
        return cls(*args, **kwargs)

    rules = [
        build(BruteForceRule, "brute_force", session),
        SuspiciousPowerShellRule(session),
        PrivilegeEscalationRule(session),
        PersistenceRule(session),
        build(
            NetworkReconRule,
            "network_recon",
            session,
            distinct_ports=PORT_SCAN_DISTINCT_PORTS,
            window_seconds=PORT_SCAN_WINDOW_SECONDS,
        ),
        build(LateralMovementRule, "lateral_movement", session),
        build(DataStagingRule, "data_staging", session),
        MalwareFileRule(session),
        build(EmailPhishingRule, "email_phishing", session),
        DnsHttpExfilRule(session),
        UsbDeviceRule(session),
        KillChainCorrelationRule(session),
        VulnerabilityRule(session),
        CredentialAccessRule(session),
        RegistryRunKeyRule(session),
        ScheduledTaskAbuseRule(session),
        WmiEventSubscriptionRule(session),
        AccountTamperingRule(session),
        MasqueradingRule(session),
        HiddenArtifactsRule(session),
        LolBinExecutionRule(session),
        ExfiltrationVolumeRule(session),
        LogClearingRule(session),
        build(C2BeaconRule, "c2_beacon", session),
        RansomwareImpactRule(session),
        InhibitRecoveryRule(session),
        CredentialStoreTheftRule(session),
        BitsJobRule(session),
        ShortcutModificationRule(session),
        KerberoastingRule(session),
        AsRepRoastingRule(session),
        DCSyncRule(session),
        GoldenTicketRule(session),
        SilverTicketRule(session),
        PassTheHashRule(session),
        PassTheTicketRule(session),
        BloodHoundReconRule(session),
        GpoAbuseRule(session),
        DllSideloadingRule(session),
        ProcessInjectionRule(session),
        TokenManipulationRule(session),
        PrintNightmareRule(session),
        SafeBootTamperingRule(session),
        AmsiBypassRule(session),
        CertificateSpoofingRule(session),
        CloudSyncExfilRule(session),
        WebhookC2Rule(session),
        DnsTunnelingRule(session),
        # ---- 52-rule native expansion (tactic groups) ----
        SpearphishingAttachmentRule(session),
        SpearphishingLinkRule(session),
        DriveByCompromiseRule(session),
        ExternalServiceExploitRule(session),
        CmdScriptExecutionRule(session),
        WmiExecutionRule(session),
        AtJobRule(session),
        ServiceExecutionRule(session),
        MsBuildExecutionRule(session),
        PythonExecutionRule(session),
        StartupFolderRule(session),
        ServiceImagePathPersistenceRule(session),
        AppInitDllRule(session),
        AccessibilityFeatureRule(session),
        IfeoDebuggerRule(session),
        NetshHelperRule(session),
        LogonScriptRule(session),
        UacBypassRule(session),
        SeDebugPrivilegeRule(session),
        NamedPipeImpersonationRule(session),
        UnquotedServicePathRule(session),
        AlwaysInstallElevatedRule(session),
        DisableDefenderRule(session),
        DisableFirewallRule(session),
        DisableAuditRule(session),
        HiddenFileAttributeRule(session),
        DisableSystemRestoreRule(session),
        LsassDumpRule(session),
        NtdsDumpRule(session),
        PasswordStoreTheftRule(session),
        KeyloggingRule(session),
        NetworkSniffingRule(session),
        CachedCredentialsRule(session),
        AccountDiscoveryRule(session),
        ShareDiscoveryRule(session),
        SystemInfoDiscoveryRule(session),
        DomainDiscoveryRule(session),
        SecuritySoftwareDiscoveryRule(session),
        FileSystemDiscoveryRule(session),
        SmbAdminShareRule(session),
        RdpLateralRule(session),
        WinRmLateralRule(session),
        SshLateralRule(session),
        ClipboardCaptureRule(session),
        ScreenCaptureRule(session),
        ArchiveCollectionRule(session),
        LocalDataCollectionRule(session),
        ProxyToolRule(session),
        UnusualPortRule(session),
        EncryptedChannelRule(session),
        ExfilAlternativeProtocolRule(session),
        ExfilWebServiceRule(session),
        SigmaRuleEngine(session),
        CorrelationEngine(session),
    ]
    return _apply_feature_flags(rules)


def _apply_feature_flags(rules: list) -> list[BaseRule]:
    """Honour the roadmap feature toggles (BARAQ_KILL_CHAIN, BARAQ_RULES_COUNT)
    and per-rule overrides (BARAQ_RULE_OVERRIDES).

    ``RULES_COUNT`` caps the number of *native* rules (0 = all); the Sigma
    engine is always kept so file-based rules keep working on constrained
    hosts. ``KILL_CHAIN=0`` drops the correlation rule. Overrides can
    disable individual rules or adjust their severity/confidence without
    touching rule code.
    """
    filtered = [
        rule
        for rule in rules
        if KILL_CHAIN or rule.rule_id != KillChainCorrelationRule.rule_id
    ]
    if RULE_OVERRIDES:
        applied = []
        for rule in filtered:
            override = RULE_OVERRIDES.get(rule.rule_id) or {}
            if override.get("enabled") is False:
                logger.info("Rule %s disabled via BARAQ_RULE_OVERRIDES", rule.rule_id)
                continue
            severity = override.get("severity")
            if severity in ("low", "medium", "high", "critical"):
                rule.severity = severity
            confidence = override.get("confidence")
            if isinstance(confidence, (int, float)) and 0.0 <= float(confidence) <= 1.0:
                rule.confidence = float(confidence)
            applied.append(rule)
        filtered = applied
    if RULES_COUNT > 0:
        natives = [r for r in filtered if r.rule_id != "sigma_rules"]
        sigma = [r for r in filtered if r.rule_id == "sigma_rules"]
        natives = natives[:RULES_COUNT]
        filtered = natives + sigma
        logger.info("BARAQ_RULES_COUNT=%d: engine trimmed to %d rules", RULES_COUNT, len(filtered))
    return filtered


class RulesEngine:
    def __init__(self, session: Session, org: str | None = None):
        self.session = session
        self.org = org
        self.rules = build_rules(session)

    def run(self, window_minutes: int = 10, since_id: int | None = None) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        for rule in self.rules:
            try:
                rule.org = self.org
                rule_findings = self._evaluate_rule(rule, window_minutes, since_id)
                for f in rule_findings:
                    if not f.mitre_id or f.mitre_id == "T0000":
                        f.mitre_id = getattr(rule, "mitre_id", "T0000")
                    if not f.recommendation:
                        f.recommendation = getattr(rule, "recommendation", "") or get_recommendation(f.mitre_id)
                findings.extend(rule_findings)
                logger.info(
                    "Rule %s: %d finding(s)", rule.rule_id, len(rule_findings)
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Rule %s failed: %s", rule.rule_id, exc)
                self.session.rollback()
        return findings

    @staticmethod
    def _evaluate_rule(rule, window_minutes: int, since_id: int | None) -> list:
        """Call a rule's evaluate(), passing the cursor only when it accepts it.

        Native rules implement ``evaluate(window_minutes)`` and keep scanning
        their (indexed) window; the Sigma engine opts in to ``since_id`` for
        incremental evaluation.
        """
        import inspect

        params = inspect.signature(rule.evaluate).parameters
        if "since_id" in params:
            return rule.evaluate(window_minutes, since_id=since_id)
        return rule.evaluate(window_minutes)


def enrich_result(result: DetectionResult) -> dict:
    """Attach MITRE ATT&CK metadata to a detection result."""
    mitre_id = result.mitre_id
    return {
        **result.to_dict(),
        "mitre_id": mitre_id,
        "mitre_name": get_technique_name(mitre_id),
        "mitre_tactic": get_tactic(mitre_id),
        "recommendation": result.recommendation or get_recommendation(mitre_id),
    }
