"""Detector D004 - Python from user-writable path (Phase 2).

Detects Python execution from locations writable by ordinary users
(Temp, AppData, Users, /home, /tmp, /dev/shm, /run/user). Python from
system locations (System32, /usr, /opt) is not suspicious.

Regression target: v1 produced questionable alerts for python runs;
this detector must explain process / path / user / host / parent /
command line where available.
"""

from __future__ import annotations

from backend.detection.context import DetectionContext
from backend.detection.contract import DETECTION
from backend.detection.evidence import ev
from backend.detection.registry import Detector
from backend.telemetry.contract import EVENT

_USER_WRITABLE_MARKERS = (
    "\\users\\",
    "/home/",
    "\\temp\\",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/user",
    "appdata\\local\\temp",
    "\\appdata\\",
)
_SYSTEM_MARKERS = (
    "\\windows\\system32",
    "\\windows\\",
    "/usr/",
    "/opt/",
    "/lib",
    "/bin",
    "/sbin",
)


def _is_python(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith("python") or lowered in ("py.exe", "pyw.exe")


def _path_from(event) -> str:
    proc = event.process or {}
    return str(
        proc.get("path")
        or proc.get("image")
        or event.facts.get("path")
        or event.facts.get("image")
        or ""
    )


class PythonWritablePathDetector(Detector):
    id = "D004"
    version = "1.0.0"
    name = "Python from User-Writable Path"
    description = (
        "Python executed from a location writable by ordinary users. "
        "Requires an explicit user-writable path; python from system "
        "locations is not suspicious."
    )
    enabled = True
    supported_event_types = ("process",)

    def evaluate(
        self, event: EVENT, context: DetectionContext | None = None
    ) -> DETECTION | None:
        proc = event.process or {}
        name = str(proc.get("name") or event.facts.get("process_name") or "")
        if not _is_python(name):
            return None

        path = _path_from(event)
        # No path -> cannot determine writability -> deterministic no.
        if not path:
            return None
        lowered = path.lower()
        if any(marker in lowered for marker in _SYSTEM_MARKERS):
            return None
        if not any(marker in lowered for marker in _USER_WRITABLE_MARKERS):
            return None

        command_line = str(
            proc.get("command_line")
            or proc.get("cmdline")
            or event.facts.get("command_line")
            or ""
        )
        parent = str(
            proc.get("parent")
            or proc.get("parent_name")
            or event.facts.get("parent_process")
            or event.facts.get("parent_name")
            or ""
        )

        in_temp = any(
            m in lowered
            for m in ("\\temp\\", "/tmp", "/var/tmp", "appdata\\local\\temp")
        )
        confidence = min(0.85, 0.70 + (0.10 if in_temp else 0.05))

        evidence = [
            ev("process", name, "Python interpreter"),
            ev("path", path, "Execution path is user-writable"),
            ev("user", event.user, "Account that started the process"),
            ev("host", event.host, "Target endpoint"),
        ]
        if parent:
            evidence.append(ev("parent_process", parent, "Parent process"))
        if command_line:
            evidence.append(ev("command_line", command_line[:200], "Full command line"))

        return DETECTION(
            detector_id=self.id,
            detector_version=self.version,
            event_id=event.fingerprint(),
            event_ids=(event.fingerprint(),),
            timestamp=event.timestamp,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            event_type=event.event_type,
            host_name=event.host,
            username=event.user,
            title="Python Execution from User-Writable Path",
            description=(
                f"Python ({name}) executed from user-writable path {path} "
                f"on {event.host} by {event.user}."
            ),
            severity="medium",
            confidence=confidence,
            mitre_tactic="Execution",
            mitre_technique="T1059.006",
            evidence=tuple(evidence),
            observables=(
                {"type": "process", "value": name},
                {"type": "file", "value": path},
                {"type": "hostname", "value": event.host},
                {"type": "user-account", "value": event.user},
            ),
            status="new",
        )
