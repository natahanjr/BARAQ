"""Registry of real-time detection rules (single-event evaluation).

These rules extend BaseRule but evaluate individual events rather than
querying the database. They are listed in the /api/detectors endpoint
alongside the v1 batch rules and v2 detectors.
"""

from __future__ import annotations

from backend.detection.rules.credential_dumping import CredentialDumpingRule
from backend.detection.rules.credential_file_access import CredentialFileAccessRule
from backend.detection.rules.disable_security_tools import DisableSecurityToolsRule
from backend.detection.rules.exfiltration_protocol import ExfiltrationProtocolRule
from backend.detection.rules.obfuscated_commands import ObfuscatedCommandRule
from backend.detection.rules.phishing import PhishingRule
from backend.detection.rules.process_injection import ProcessInjectionRule
from backend.detection.rules.protocol_tunneling import ProtocolTunnelingRule
from backend.detection.rules.ransomware import RansomwareRule
from backend.detection.rules.registry_runkey_persistence import RegistryRunKeyRule
from backend.detection.rules.remote_discovery import RemoteDiscoveryRule
from backend.detection.rules.scheduled_task_suspicious import ScheduledTaskCreationRule
from backend.detection.rules.scripting_interpreter import ScriptingInterpreterRule
from backend.detection.rules.token_manipulation import TokenManipulationRule

_CATEGORIES = {
    "BARAQ-CRED-002": "credential-access",
    "BARAQ-CRED-001": "credential-access",
    "BARAQ-EVASION-004": "defense-evasion",
    "BARAQ-EXFIL-002": "exfiltration",
    "BARAQ-EVASION-001": "defense-evasion",
    "BARAQ-INITIAL-003": "initial-access",
    "BARAQ-EVASION-003": "defense-evasion",
    "BARAQ-C2-005": "command-and-control",
    "BARAQ-IMPACT-001": "impact",
    "BARAQ-PERSIST-011": "persistence",
    "BARAQ-DISC-001": "discovery",
    "BARAQ-PERSIST-010": "persistence",
    "BARAQ-EXEC-003": "execution",
    "BARAQ-PRIV-003": "privilege-escalation",
}

_ALL_RULES = [
    CredentialDumpingRule,
    CredentialFileAccessRule,
    DisableSecurityToolsRule,
    ExfiltrationProtocolRule,
    ObfuscatedCommandRule,
    PhishingRule,
    ProcessInjectionRule,
    ProtocolTunnelingRule,
    RansomwareRule,
    RegistryRunKeyRule,
    RemoteDiscoveryRule,
    ScheduledTaskCreationRule,
    ScriptingInterpreterRule,
    TokenManipulationRule,
]


def _rule_to_dict(cls) -> dict:
    return {
        "id": cls.rule_id,
        "detector_id": cls.rule_id,
        "name": getattr(cls, "title", None) or getattr(cls, "name", cls.rule_id),
        "description": cls.description,
        "severity": cls.severity,
        "mitre_technique": cls.mitre_id,
        "mitre_id": cls.mitre_id,
        "confidence": cls.confidence,
        "enabled": True,
        "category": _CATEGORIES.get(cls.rule_id, "general"),
        "version": "1.0.0",
        "source": "realtime",
    }


REALTIME_RULES = [_rule_to_dict(cls) for cls in _ALL_RULES]
