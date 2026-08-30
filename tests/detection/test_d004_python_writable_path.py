"""Detector D004 - Python from user-writable path tests (Phase 2)."""

from __future__ import annotations

from backend.detection.engine import run_detection
from tests.detection.helpers import event


def d004(event):
    findings = [f for f in run_detection(event) if f.detector_id == "D004"]
    return findings[0] if findings else None


def py(path: str, name: str = "python.exe") -> event.__class__:
    return event(
        action="process_start",
        event_type="process",
        user="alice",
        process={"name": name, "path": path, "command_line": f"{name} {path}"},
        facts={"path": path},
    )


# positive ----------------------------------------------------------------------


def test_python_from_temp_detected():
    detection = d004(py("C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"))
    assert detection is not None
    assert detection.severity == "medium"
    assert detection.mitre_technique == "T1059.006"
    assert detection.username == "alice"
    assert any(e.field == "path" for e in detection.evidence)


def test_python_from_home_detected():
    assert d004(py("/home/alice/.cache/x.py")) is not None


def test_python_from_public_detected():
    assert d004(py("C:\\Users\\Public\\script.py")) is not None


# negative ----------------------------------------------------------------------


def test_python_from_system32_not_detected():
    assert d004(py("C:\\Windows\\System32\\python.exe")) is None


def test_python_from_usr_not_detected():
    assert d004(py("/usr/bin/python3")) is None


def test_non_python_not_detected():
    detection = event(
        action="process_start",
        event_type="process",
        process={"name": "notepad.exe", "path": "C:\\Users\\alice\\Temp\\notes.txt"},
        facts={},
    )
    assert d004(detection) is None


# boundary ----------------------------------------------------------------------


def test_missing_path_no_detection():
    detection = event(
        action="process_start",
        event_type="process",
        process={"name": "python.exe"},
        facts={},
    )
    assert d004(detection) is None


def test_pythonw_supported():
    assert (
        d004(py("C:\\Users\\alice\\Downloads\\x.pyw", name="pythonw.exe")) is not None
    )


def test_confidence_grows_in_temp():
    home = d004(py("C:\\Users\\alice\\script.py"))
    temp = d004(py("C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"))
    assert temp.confidence >= home.confidence
    assert 0.0 <= temp.confidence <= 1.0


# missing field / duplicate / multiple event -------------------------------------


def test_empty_command_line_still_detected_with_path():
    detection = event(
        action="process_start",
        event_type="process",
        user="alice",
        process={
            "name": "python.exe",
            "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py",
        },
        facts={},
    )
    assert d004(detection) is not None


def test_duplicate_event_same_detection_id():
    a = d004(py("C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"))
    b = d004(py("C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"))
    assert a.detection_id == b.detection_id


def test_single_event_single_detection():
    findings = run_detection(py("C:\\Users\\alice\\AppData\\Local\\Temp\\tool.py"))
    assert len([f for f in findings if f.detector_id == "D004"]) == 1
