"""Regression: developer-workflow false positives must be demoted, and the
Windows "description could not be found" template must never become telemetry.

Live symptom (2026-08-24): opencode.exe/python.exe launching signed
powershell.exe tripped generic Sigma rules; alerts stayed HIGH because
(a) Sigma findings carry rule="sigma_rules", which was never in the demotion
allow-list, and (b) the Sigma engine reports a hardcoded 0.8 confidence that
defeated the low-confidence gate. Alert bodies additionally embedded Windows'
literal template placeholder prose.
"""

from __future__ import annotations

from backend.context.engine import assess_text

_PLACEHOLDER = (
    "<The description for Event ID ( 4688 ) in Source "
    "( 'Microsoft-Windows-Security-Auditing' ) could not be found. It contains "
    "the following insertion string(s):'S-1-5-21-1, Haaraphel, HAARAPHEL, "
    "0x6967ba81, 0x2038, C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\"
    "powershell.exe, %%1938, 0x2038, powershell -NoProfile -WindowStyle Hidden'"
)


# ---------------------------------------------------------------------------
# Problem 1: sigma findings under strong dev context get demoted
# ---------------------------------------------------------------------------

_DEV_EVIDENCE = (
    "Sigma 'BARAQ - PowerShell Encoded Command' matched event 4688 (Process) "
    "- user 'Haaraphel': powershell.exe launched under developer tooling. "
    "process 'powershell.exe' reputation=trusted "
    "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
    "parent process(es): python.exe opencode.exe "
    "command 'python -m pytest tests/' "
    "C:\\Users\\dev\\Projects\\baraq\\venv\\Scripts\\python.exe"
)


def test_sigma_finding_demoted_under_strong_dev_context():
    facts = assess_text(_DEV_EVIDENCE, rule="sigma_rules")
    assert facts.strong_dev_context is True
    assert facts.severity_adjust(0.8) == "demote"


def test_native_rule_still_requires_low_confidence():
    # Native dev-sensitive rules keep the original low-confidence gate.
    facts = assess_text(_DEV_EVIDENCE, rule="suspicious_powershell")
    assert facts.severity_adjust(0.85) is None
    assert facts.severity_adjust(0.6) == "demote"


def test_no_demotion_without_dev_context():
    benign = """
    Sigma 'Brute Force' matched event 4625 (Logon)
    Context:
      process 'unknown_tool.exe' reputation=unknown (C:\\Temp\\tool.exe)
      destination 185.220.101.44:443
    """
    facts = assess_text(benign, rule="sigma_rules")
    assert facts.strong_dev_context is False
    assert facts.severity_adjust(0.8) is None


def test_unknown_subject_blocks_parent_based_demotion():
    # A real threat hiding behind a dev parent: unknown binary spawned BY
    # python.exe must NOT auto-demote.
    facts = assess_text(
        "process 'implant.exe' reputation=unknown (C:\\Temp\\implant.exe) "
        "parent process(es): python.exe",
        rule="sigma_rules",
    )
    assert facts.severity_adjust(0.8) is None


def test_browser_parent_does_not_count_as_dev_context():
    facts = assess_text(
        "process 'powershell.exe' reputation=trusted "
        "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
        "parent process(es): chrome.exe",
        rule="sigma_rules",
    )
    assert facts.strong_dev_context is False
    assert facts.severity_adjust(0.8) is None


# ---------------------------------------------------------------------------
# Problem 2: placeholder template prose never becomes the stored message
# ---------------------------------------------------------------------------


def test_normalizer_rejects_placeholder_template_message():
    from backend.analyzers.normalizer import Normalizer

    record = {
        "event_id": 4688,
        "source": "eventlog",
        "timestamp": "2026-08-24T13:41:00+00:00",
        "message": _PLACEHOLDER,
        "raw": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -NoProfile -WindowStyle Hidden -Command Get-Help",
            "ParentProcessName": "C:\\tools\\opencode.exe",
        },
    }
    n = Normalizer().normalize(record)
    assert "could not be found" not in n["message"]
    assert "insertion string" not in n["message"]


def test_placeholder_regex_matches_windows_wording_variants():
    from backend.analyzers.normalizer import _TEMPLATE_PLACEHOLDER_RE as rx

    assert rx.search(_PLACEHOLDER)
    assert rx.search(
        "The description for Event ID ( 4624 ) in Source ( Security ) "
        "cannot be found. It contains the following insertion string(s): x"
    ) or rx.search(
        "The description for Event ID ( 4624 ) in Source ( Security ) "
        "could not be found. It contains the following insertion string(s): x"
    )
    assert not rx.search("Normal process creation message: svchost.exe")


# ---------------------------------------------------------------------------
# Problem 3 (deep defence): strong dev context + known-good binaries means
# the finding is never stored as an alert at all.
# ---------------------------------------------------------------------------


def _gate(facts, rule):
    from backend.detection.alerting import _is_dev_workflow_fp

    return _is_dev_workflow_fp(facts, rule)


def test_dev_workflow_finding_is_dropped_not_alerted():
    facts = assess_text(_DEV_EVIDENCE, rule="sigma_rules")
    assert facts.strong_dev_context is True
    assert _gate(facts, "sigma_rules") is True
    assert _gate(facts, "") is True


def test_gate_spares_high_fidelity_rules():
    facts = assess_text(_DEV_EVIDENCE, rule="brute_force")
    # Even with dev context, brute-force detections always alert.
    assert _gate(facts, "brute_force") is False


def test_gate_blocks_when_unknown_binary_present():
    facts = assess_text(
        "process 'implant.exe' reputation=unknown (C:\\Temp\\implant.exe) "
        "process 'powershell.exe' reputation=trusted "
        "(C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe) "
        "parent process(es): python.exe",
        rule="sigma_rules",
    )
    # Unknown-reputation subject suppresses the parent-based dev verdict, so
    # neither the silent drop nor the demotion layer applies - the finding
    # flows through the normal pipeline at full severity.
    assert facts.strong_dev_context is False
    assert facts.severity_adjust(0.8) is None
    assert _gate(facts, "sigma_rules") is False


def test_pure_system_chain_is_dropped():
    # services.exe -> svchost.exe: genuine Windows internals misfiring a
    # generic Sigma rule - OS noise, never an alert.
    facts = assess_text(
        "process 'svchost.exe' reputation=system "
        "(C:\\Windows\\System32\\svchost.exe) "
        "parent process(es): services.exe",
        rule="sigma_rules",
    )
    assert _gate(facts, "sigma_rules") is True
