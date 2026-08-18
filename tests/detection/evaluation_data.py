"""Phase 2 evaluation dataset (SC-001..SC-008).

Eight labeled scenarios - the official Phase 2 benchmark. Every scenario is
a list of raw telemetry records plus the expected detectors to fire (and
their severities). The metrics runner (``test_evaluation.py``) replays the
records through the real pipeline (ingest -> detect -> persist) and reports
TP/FP/FN/TN, precision, recall, F1 and FPR.

Labeling follows SOC_CONTRACT.md:
    TP  detection fired and the scenario is genuinely malicious
    FP  detection fired but the scenario is benign
    FN  no detection but the scenario is malicious
    TN  no detection and the scenario is benign

Methodology notes (see docs/phase2/PHASE2_ACCEPTANCE.md):
    * n = 8 scenarios - a small, fully human-labeled benchmark, not a claim
      of production-grade statistical confidence (no fake confidence).
    * Scenario datasets are checked in, immutable, and replayed verbatim.
"""
from __future__ import annotations

from datetime import datetime, timezone

T0 = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)


def _ts(minutes: float) -> str:
    from datetime import timedelta

    return (T0 - timedelta(minutes=minutes)).isoformat()


# --- scenario builders ---------------------------------------------------------

SC_001_BENIGN_LOGIN = {
    "id": "SC-001",
    "name": "benign interactive login from internal IP",
    "label": "TN",
    "expected": [],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "windows-security",
            "host": "workstation-42",
            "user": "alice",
            "action": "logon",
            "facts": {"logon_type": 2},
            "network": {"src_ip": "10.0.0.5"},
        }
    ],
}

SC_002_EXTERNAL_RDP = {
    "id": "SC-002",
    "name": "external RDP logon (logon type 10, public IP)",
    "label": "TP",
    "expected": [{"detector_id": "D001", "severity": "high"}],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "windows-security",
            "host": "workstation-42",
            "user": "alice",
            "action": "logon",
            "facts": {"logon_type": 10},
            "network": {"src_ip": "203.0.113.5"},
        }
    ],
}

SC_003_BRUTE_FORCE = {
    "id": "SC-003",
    "name": "10 failed logons for one account in 15 minutes",
    "label": "TP",
    "expected": [{"detector_id": "D002", "severity": "medium"}],
    "records": [
        {
            "timestamp": _ts(i * 0.5),
            "source": "windows-security",
            "host": "workstation-42",
            "user": "alice",
            "action": "logon_failed",
            "facts": {"source_ip": "198.51.100.7"},
            "network": {"src_ip": "198.51.100.7"},
        }
        for i in range(10)
    ],
}

SC_004_SUSPICIOUS_POWERSHELL = {
    "id": "SC-004",
    "name": "encoded PowerShell command from Temp",
    "label": "TP",
    "expected": [{"detector_id": "D003", "severity": "high"}],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "sysmon",
            "host": "workstation-42",
            "user": "alice",
            "action": "process_start",
            "facts": {"command_line": "powershell.exe -EncodedCommand SQBFAFgA -w hidden",
                      "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.ps1"},
            "process": {"name": "powershell.exe",
                        "command_line": "powershell.exe -EncodedCommand SQBFAFgA -w hidden",
                        "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\x.ps1"},
        }
    ],
}

SC_005_PYTHON_WRITABLE_PATH = {
    "id": "SC-005",
    "name": "python from AppData Local Temp",
    "label": "TP",
    "expected": [{"detector_id": "D004", "severity": "medium"}],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "sysmon",
            "host": "workstation-42",
            "user": "alice",
            "action": "process_start",
            "facts": {"path": "C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"},
            "process": {"name": "python.exe", "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"},
        }
    ],
}

SC_006_RANSOMWARE_BEHAVIOR = {
    "id": "SC-006",
    "name": "20 file modifications in 5 minutes on one host",
    "label": "TP",
    "expected": [{"detector_id": "D005", "severity": "medium"}],
    "records": [
        {
            "timestamp": _ts(i * 0.2),
            "source": "sysmon",
            "host": "workstation-42",
            "user": "-",
            "action": "file_modify",
            "facts": {"path": f"C:\\data\\docs\\file{i}.docx"},
            "process": {"name": "evil.exe"},
        }
        for i in range(20)
    ],
}

SC_007_PYTHON_SYSTEM_PATH = {
    "id": "SC-007",
    "name": "python from System32 (benign)",
    "label": "TN",
    "expected": [],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "sysmon",
            "host": "workstation-42",
            "user": "alice",
            "action": "process_start",
            "facts": {"path": "C:\\Windows\\System32\\python.exe"},
            "process": {"name": "python.exe", "path": "C:\\Windows\\System32\\python.exe"},
        }
    ],
}

SC_008_SINGLE_FILE_MODIFICATION = {
    "id": "SC-008",
    "name": "single file modification (benign)",
    "label": "TN",
    "expected": [],
    "records": [
        {
            "timestamp": _ts(1),
            "source": "sysmon",
            "host": "workstation-42",
            "user": "-",
            "action": "file_modify",
            "facts": {"path": "C:\\data\\docs\\report.docx"},
            "process": {"name": "word.exe"},
        }
    ],
}

SCENARIOS = [
    SC_001_BENIGN_LOGIN,
    SC_002_EXTERNAL_RDP,
    SC_003_BRUTE_FORCE,
    SC_004_SUSPICIOUS_POWERSHELL,
    SC_005_PYTHON_WRITABLE_PATH,
    SC_006_RANSOMWARE_BEHAVIOR,
    SC_007_PYTHON_SYSTEM_PATH,
    SC_008_SINGLE_FILE_MODIFICATION,
]


def expected_detector_ids(scenario: dict) -> set[str]:
    return {exp["detector_id"] for exp in scenario["expected"]}