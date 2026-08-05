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
from backend.mitre.attack import get_recommendation, get_tactic, get_technique_name

logger = logging.getLogger("sentinel.detection")


def build_rules(session: Session) -> list[BaseRule]:
    """Instantiate all detection rules (the platform's rule set)."""
    return [
        BruteForceRule(session),
        SuspiciousPowerShellRule(session),
        PrivilegeEscalationRule(session),
        PersistenceRule(session),
        NetworkReconRule(session),
        LateralMovementRule(session),
        DataStagingRule(session),
        MalwareFileRule(session),
        EmailPhishingRule(session),
        DnsHttpExfilRule(session),
        UsbDeviceRule(session),
        KillChainCorrelationRule(session),
    ]


class RulesEngine:
    def __init__(self, session: Session):
        self.session = session
        self.rules = build_rules(session)

    def run(self, window_minutes: int = 10) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        for rule in self.rules:
            try:
                rule_findings = rule.evaluate(window_minutes)
                for f in rule_findings:
                    f.mitre_id = getattr(rule, "mitre_id", "T0000")
                    f.recommendation = getattr(rule, "recommendation", "") or get_recommendation(f.mitre_id)
                findings.extend(rule_findings)
                logger.info(
                    "Rule %s: %d finding(s)", rule.rule_id, len(rule_findings)
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Rule %s failed: %s", rule.rule_id, exc)
        return findings


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
