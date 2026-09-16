"""T1053.005 - Scheduled Task/Job: Scheduled Task Creation.

Detects suspicious scheduled task creation via schtasks.exe or
at.exe, especially with remote targets, SYSTEM privileges, or
executable paths in temp/writable directories.
"""

from __future__ import annotations

from backend.detection.rules.base import BaseRule, DetectionResult

SUSPICIOUS_TASK_PATTERNS = [
    "schtasks /create",
    "schtasks.exe /create",
    "schtasks /change",
    "/sc onlogon",
    "/sc onstart",
    "/sc onidle",
    "/ru system",
    "/ru \"system\"",
    "/rp *",
    "/rl highest",
    "at \\\\",
    "at.exe \\\\",
]

SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\perflogs\\",
]

SUSPICIOUS_NAMES = [
    "update",
    "cleanup",
    "maintenance",
    "system",
    "service",
    "health",
    "monitor",
    "check",
    "sync",
    "backup",
    "debug",
    "test",
    "helper",
    "assistant",
]


class ScheduledTaskCreationRule(BaseRule):
    rule_id = "BARAQ-PERSIST-010"
    title = "Suspicious Scheduled Task Creation"
    description = "Detects suspicious scheduled task creation or modification"
    mitre_id = "T1053.005"
    severity = "medium"
    confidence = 0.70

    def evaluate(self, event: dict) -> DetectionResult | None:
        if event.get("source") != "process":
            return None
        cmdline = (event.get("command_line") or "").lower()
        if not cmdline:
            return None

        is_schtasks = any(p in cmdline for p in SUSPICIOUS_TASK_PATTERNS)
        if not is_schtasks:
            return None

        evidence = ["Scheduled task creation detected"]

        for path in SUSPICIOUS_PATHS:
            if path in cmdline:
                evidence.append(f"Task binary in suspicious path: {path}")
                break

        for name in SUSPICIOUS_NAMES:
            if f"/tn {name}" in cmdline or f"/tn \"{name}" in cmdline:
                evidence.append(f"Suspicious task name: {name}")
                break

        if "/ru system" in cmdline or "/ru \"system\"" in cmdline:
            evidence.append("Task runs as SYSTEM")
            return DetectionResult(
                confidence=0.9,
                severity="critical",
                mitre_id=self.mitre_id,
                evidence=evidence,
                recommendation="Investigate scheduled task for persistence",
            )

        if "/rl highest" in cmdline:
            evidence.append("Task runs with highest privileges")
            return DetectionResult(
                confidence=0.85,
                severity="high",
                mitre_id=self.mitre_id,
                evidence=evidence,
                recommendation="Review task privileges and creator",
            )

        return DetectionResult(
            confidence=self.confidence,
            severity=self.severity,
            mitre_id=self.mitre_id,
            evidence=evidence,
            recommendation="Verify task creation is authorized",
        )
