"""P0-1 tests: event normalization & data integrity.

The analyst interface must never receive SafeFormatMessage debris
("New Process Name: C", "Process Command Line: \\\"") - truncated message
values are repaired from the authoritative structured copy, and lossy
sources are flagged with data_integrity + repair metadata.
"""

from __future__ import annotations

from backend.analyzers.normalizer import Normalizer
from backend.collectors.validation import is_debris_value


def _mk_4688(structured: dict, message: str) -> dict:
    return {
        "source": "eventlog",
        "channel": "Security",
        "event_id": 4688,
        "timestamp": "2026-08-16T10:00:00",
        "user": "-",
        "host": "WS-DEV",
        "message": message,
        "raw": {
            "provider": "Microsoft-Windows-Security-Auditing",
            "record_number": 42,
            **structured,
        },
    }


TRUNCATED_MESSAGE = (
    "A new process has been created.\n"
    "New Process Name: C\n"
    'Process Command Line: "\n'
    "Creator Process Name: C"
)

STRUCTURED = {
    "NewProcessName": "C:\\Users\\haaraphel\\venv\\Scripts\\python.exe",
    "CommandLine": '"C:\\Users\\haaraphel\\venv\\Scripts\\python.exe" -m pytest tests/',
    "CreatorProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
}


def test_debris_values_detected():
    assert is_debris_value("C") is True
    assert is_debris_value('"') is True
    assert is_debris_value("g") is True
    assert is_debris_value("C:\\Windows\\System32\\cmd.exe") is False
    assert is_debris_value('"C:\\app\\run.exe" /c x') is False


def test_repair_message_from_structured_facts():
    repaired, fields = Normalizer.repair_message(TRUNCATED_MESSAGE, STRUCTURED)
    assert (
        "New Process Name: C:\\Users\\haaraphel\\venv\\Scripts\\python.exe" in repaired
    )
    assert (
        "Creator Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        in repaired
    )
    assert "python.exe" in repaired
    assert "C\n" not in repaired
    assert set(fields) == {
        "New Process Name",
        "Process Command Line",
        "Creator Process Name",
    }


def test_clean_message_untouched():
    clean = "A new process has been created.\nNew Process Name: C:\\Windows\\System32\\cmd.exe"
    repaired, fields = Normalizer.repair_message(clean, STRUCTURED)
    assert repaired == clean
    assert fields == []


def test_debris_without_structured_facts_left_alone():
    repaired, fields = Normalizer.repair_message(
        TRUNCATED_MESSAGE, {"NewProcessName": "C"}
    )
    assert fields == []  # no authoritative copy to repair from
    assert "New Process Name: C" in repaired


def test_normalize_repairs_message_and_flags_integrity():
    norm = Normalizer(hostname="WS-DEV")
    out = norm.normalize(_mk_4688(STRUCTURED, TRUNCATED_MESSAGE))

    assert (
        "New Process Name: C:\\Users\\haaraphel\\venv\\Scripts\\python.exe"
        in out["message"]
    )
    assert out["data_integrity"] == "truncated"
    di = out["raw_json"]["data_integrity"]
    assert di["truncated_fields"] == ["message"]
    assert di["repaired_fields"] == [
        "New Process Name",
        "Process Command Line",
        "Creator Process Name",
    ]
    assert out["raw_json"]["facts"]["NewProcessName"] == STRUCTURED["NewProcessName"]
    assert out["raw_json"]["facts"]["CommandLine"] == STRUCTURED["CommandLine"]


def test_normalize_clean_message_stays_complete():
    norm = Normalizer(hostname="WS-DEV")
    clean = "A new process has been created.\nNew Process Name: C:\\Windows\\System32\\cmd.exe"
    out = norm.normalize(_mk_4688(STRUCTURED, clean))
    assert out["data_integrity"] == "complete"
    assert out["message"] == clean
    assert out["raw_json"]["data_integrity"]["repaired_fields"] == []


def test_normalize_repairs_sysmon_style_message():
    norm = Normalizer(hostname="WS-DEV")
    msg = 'Process Create:\nProcessName: C\nImage: C\nCommandLine: "'
    out = norm.normalize(
        _mk_4688(
            {
                "NewProcessName": "C:\\tools\\node.exe",
                "CommandLine": "node server.js",
                "Image": "C:\\tools\\node.exe",
            },
            msg,
        )
    )
    assert "CommandLine: node server.js" in out["message"]
    assert "node.exe" in out["message"]
    assert out["raw_json"]["data_integrity"]["repaired_fields"]


def test_corrupted_event_discarded_by_pipeline_validation(db):
    """Fully-corrupted (no structured copy) process events never reach storage."""
    from backend.api.system import run_pipeline

    rec = _mk_4688({}, TRUNCATED_MESSAGE)
    result = run_pipeline(db, [rec], org="univ-a")
    assert result["saved_events"] == 0
    assert result["corrupted_events"] == 1


def test_stored_event_message_is_clean_end_to_end(db):
    """The event that reaches the UI carries the repaired message."""
    from backend.api.system import run_pipeline
    from backend.database.models import NormalizedEvent

    run_pipeline(db, [_mk_4688(STRUCTURED, TRUNCATED_MESSAGE)], org="univ-a")
    events = db.query(NormalizedEvent).filter(NormalizedEvent.event_id == 4688).all()
    assert events
    for ev in events:
        assert "python.exe" in ev.message
        assert "New Process Name: C\n" not in ev.message
