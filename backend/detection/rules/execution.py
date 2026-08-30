"""Rule set - Execution techniques (TA0002).

Covers command-line script engines (T1059.003), WMI remote execution
(T1047), service creation (T1569.002), AT jobs (T1053.002), script
interpreters from user-writable locations (T1059.006/007) and build
tool abuse (T1127.001).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from backend.detection.rules.base import BaseRule, DetectionResult

_SUSPICIOUS_DIRS = re.compile(
    r"\\Temp\\|\\Users\\Public\\|\\AppData\\|\\Downloads\\|\\ProgramData\\",
    re.IGNORECASE,
)

_CMD_ENC = re.compile(
    r"\bcmd(?:\.exe)?\s+/[cC]\b[^\n]*?(?<!\w)(?:/enc(?:oded)?\b|/u\b|base64|powershell(?:\.exe)?\s+-e)",
    re.IGNORECASE,
)
_WMIC_EXEC = re.compile(
    r"\bwmic(?:\.exe)?\b[^\n]*?\b(?:process\s+call\s+create|process\s+creation\s+commandline|/node:)\b|"
    r"\bInvoke-WmiMethod\b[^\n]*\b-Credential\b|"
    r"\bGet-WmiObject\b[^\n]*(?<!\w)-ComputerName\b",
    re.IGNORECASE,
)
_AT_JOB = re.compile(r"\bat(?:\.exe)?\b\s+\d{1,2}:\d{2}", re.IGNORECASE)
_SERVICE_CREATE = re.compile(
    r"\bsc(?:\.exe)?\b\s+(?:create|config)\b[^\n]*?(?:\bbinpath\b|=)",
    re.IGNORECASE,
)
_MSBUILD = re.compile(r"\bmsbuild(?:\.exe)?\b", re.IGNORECASE)
_PYTHON = re.compile(r"\b(?:python|py|python3)(?:\.exe|\d*\.exe)?\b", re.IGNORECASE)


class CmdScriptExecutionRule(BaseRule):
    rule_id = "cmd_script_execution"
    name = "Suspicious Cmd.exe Scripting"
    description = (
        "cmd.exe was invoked with encoded or nested-script arguments - a "
        "technique used to hide command lines from process auditing."
    )
    severity = "high"
    confidence = 0.75
    mitre_id = "T1059.003"
    recommendation = (
        "Review the decoded command line, inspect the parent process, and "
        "consider auditing cmd.exe invocation via Sysmon CommandLine."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _CMD_ENC.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Encoded / nested cmd.exe invocation by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class WmiExecutionRule(BaseRule):
    rule_id = "wmi_execution"
    name = "WMI Remote Process Execution"
    description = (
        "WMI was used to launch a process, often against a remote host - a "
        "favorite lateral-movement execution primitive."
    )
    severity = "high"
    confidence = 0.8
    mitre_id = "T1047"
    recommendation = (
        "Audit WMI activity (enable WMI audit events), verify the remote "
        "target host, and review Win32_Process Create activity on endpoints."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _WMIC_EXEC.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"WMI process execution by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class AtJobRule(BaseRule):
    rule_id = "at_job"
    name = "AT Job Scheduled Execution"
    description = (
        "The legacy AT scheduler was used to queue a job - a persistence and "
        "execution technique frequently abused on older workstations."
    )
    severity = "medium"
    confidence = 0.6
    mitre_id = "T1053.002"
    recommendation = (
        "Convert legacy AT jobs to Scheduled Tasks with restricted accounts, "
        "and audit AT job creation on all hosts."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _AT_JOB.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"AT job created by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class ServiceExecutionRule(BaseRule):
    rule_id = "service_execution"
    name = "Suspicious Service Creation"
    description = (
        "sc.exe was used to create or reconfigure a service - abuse of "
        "Windows services to execute arbitrary binaries with elevated "
        "privileges."
    )
    severity = "high"
    confidence = 0.7
    mitre_id = "T1569.002"
    recommendation = (
        "Review the service binary path, delete unauthorized services, and "
        "restrict service creation to administrators with justification."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _SERVICE_CREATE.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Service created/configured via sc.exe by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class MsBuildExecutionRule(BaseRule):
    rule_id = "msbuild_execution"
    name = "MSBuild Execution"
    description = (
        "MSBuild was invoked - a signed build tool used by attackers to "
        "execute inline C# payloads and evade application allow-lists."
    )
    severity = "medium"
    confidence = 0.7
    mitre_id = "T1127.001"
    recommendation = (
        "Verify the project file content, restrict MSBuild to build "
        "pipelines, and review the parent process chain."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _MSBUILD.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"MSBuild invoked by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings


class PythonExecutionRule(BaseRule):
    rule_id = "python_execution"
    name = "Python Execution from User-Writable Path"
    description = (
        "A Python interpreter was launched from a user-writable directory - "
        "consistent with dropped payload execution rather than a system "
        "installation."
    )
    severity = "medium"
    confidence = 0.65
    mitre_id = "T1059.006"
    recommendation = (
        "Inspect the interpreter binary and script, review the parent "
        "process, and scan the originating directory for additional payloads."
    )

    def evaluate(self, window_minutes: int) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        since = datetime.now(UTC) - timedelta(minutes=window_minutes)
        for cmdline, label, user in self.cmdline_candidates(since):
            if not _PYTHON.search(cmdline):
                continue
            # Only suspicious when the interpreter path or script is in a
            # user-writable directory.
            if not _SUSPICIOUS_DIRS.search(cmdline):
                continue
            findings.append(
                self._result(
                    evidence=(
                        f"Python executed from user-writable path by '{user}' ({label}). "
                        f"Command line: {cmdline[:300]}"
                    ),
                    event_ids=[],
                )
            )
        return findings
