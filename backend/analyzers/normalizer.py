"""Event Processing Engine - normalizes raw collector records.

Converts a heterogeneous raw record:

    {source: "eventlog", event_id: 4625, message: "...", raw: {...}}

into the canonical BARAQ event:

    Event ID: 4625 | Category: Authentication | User: Admin | Risk: Medium | Timestamp: ...

Also parses structured facts (source IPs, logon types, accounts, binaries)
out of messages so detection rules can reason over real data.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

logger = logging.getLogger("baraq.analyzers.normalizer")

# Numeric risk scale (0-100) per risk band; enables risk-based prioritization.
RISK_BAND_SCORES = {"Low": 15, "Medium": 45, "High": 75}

#: Cap applied to the formatted message (collector and DB). A message longer
#: than this is evidence that data was cut somewhere in the pipeline.
MAX_MESSAGE_LEN = 8192

#: Explicit markers left behind when Windows truncates a long value.
_TRUNCATION_MARKERS = ("...", "\t")

#: A complete Windows process path ends with one of these executable suffixes.
_EXEC_SUFFIXES = (".exe", ".com", ".bat", ".cmd", ".ps1", ".dll", ".scr", ".vbs", ".js", ".msi", ".jar")

#: Structured fields whose completeness the normalizer can reason about.
_STRUCTURED_PROCESS_KEYS = ("NewProcessName", "ParentProcessName", "Image", "CommandLine", "ScriptBlockText")

#: Event IDs whose process facts drive detection and must arrive intact.
_PROCESS_EVENT_IDS = (4688, 1, 4104, 4103)

#: Message field label -> authoritative structured facts keys (priority
#: order). SafeFormatMessage truncates these values to 1-char debris
#: ("New Process Name: C"); the structured XML copy is complete and wins.
_MESSAGE_LABEL_FACTS = {
    "New Process Name": ("NewProcessName", "new_process"),
    "Creator Process Name": ("CreatorProcessName", "creator_process"),
    "Process Name": ("Image", "image", "NewProcessName", "new_process"),
    "Parent Process Name": ("ParentProcessName", "parent_image", "parent_process"),
    "ParentProcessName": ("ParentProcessName", "parent_image", "parent_process"),
    "Process Command Line": ("CommandLine", "command_line"),
    "CommandLine": ("CommandLine", "command_line"),
    "Command Line": ("CommandLine", "command_line"),
    "Image": ("Image", "image"),
    "TargetImage": ("TargetImage", "target_image"),
}
_FIELD_LINE_RE = re.compile(r"^([A-Za-z][A-Za-z ]+):\s*(.*)$")

#: Windows renders events whose provider message template is not registered
#: with this literal sentence + raw insertion strings. It is formatter debris,
#: never real telemetry.
_TEMPLATE_PLACEHOLDER_RE = re.compile(
    r"The description for Event ID\s*\(\s*\d+\s*\).*?"
    r"insertion string\(s\)\s*:\s*",
    re.DOTALL | re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Event metadata tables
# ---------------------------------------------------------------------------
EVENT_META: dict[int, dict[str, str]] = {
    4624: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4625: {"category": "Authentication", "risk": "Medium", "severity": "low"},
    4634: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4647: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4648: {"category": "Authentication", "risk": "Medium", "severity": "low"},
    4672: {"category": "Privilege", "risk": "Medium", "severity": "medium"},
    4688: {"category": "Process", "risk": "Low", "severity": "info"},
    4720: {"category": "Account Management", "risk": "High", "severity": "medium"},
    4722: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4724: {"category": "Account Management", "risk": "High", "severity": "high"},
    4725: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4726: {"category": "Account Management", "risk": "High", "severity": "high"},
    4728: {"category": "Account Management", "risk": "High", "severity": "high"},
    4732: {"category": "Account Management", "risk": "High", "severity": "high"},
    4734: {"category": "Account Management", "risk": "Medium", "severity": "medium"},
    4740: {"category": "Authentication", "risk": "Medium", "severity": "medium"},
    4768: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4769: {"category": "Authentication", "risk": "Low", "severity": "info"},
    4771: {"category": "Authentication", "risk": "Medium", "severity": "medium"},
    4698: {"category": "Persistence", "risk": "High", "severity": "medium"},
    4702: {"category": "Persistence", "risk": "High", "severity": "high"},
    7036: {"category": "Service", "risk": "Low", "severity": "info"},
    7040: {"category": "Service", "risk": "Medium", "severity": "medium"},
    7045: {"category": "Service", "risk": "High", "severity": "medium"},
    4103: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
    4104: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
    400: {"category": "PowerShell", "risk": "Low", "severity": "info"},
    403: {"category": "PowerShell", "risk": "Medium", "severity": "medium"},
    6416: {"category": "Device", "risk": "Medium", "severity": "medium"},
    6420: {"category": "Device", "risk": "Medium", "severity": "medium"},
    1: {"category": "Process", "risk": "Low", "severity": "info"},
    3: {"category": "Network", "risk": "Low", "severity": "info"},
    10: {"category": "Process", "risk": "High", "severity": "high"},
    11: {"category": "File", "risk": "Medium", "severity": "medium"},
    13: {"category": "Registry", "risk": "Medium", "severity": "medium"},
    23: {"category": "File", "risk": "Low", "severity": "info"},
    104: {"category": "Log Clearing", "risk": "High", "severity": "high"},
    1102: {"category": "Log Clearing", "risk": "High", "severity": "high"},
    4738: {"category": "Account Management", "risk": "High", "severity": "high"},
    4662: {"category": "Directory Service", "risk": "Medium", "severity": "medium"},
    4768: {"category": "Authentication", "risk": "Medium", "severity": "medium"},
    4769: {"category": "Authentication", "risk": "Low", "severity": "low"},
    5136: {"category": "Directory Service", "risk": "High", "severity": "high"},
    7: {"category": "Process", "risk": "Medium", "severity": "medium"},
    8: {"category": "Process", "risk": "High", "severity": "high"},
    # Application channel
    1000: {"category": "Application Crash", "risk": "Low", "severity": "info"},
    1001: {"category": "Application Error", "risk": "Low", "severity": "info"},
    1002: {"category": "Application Hang", "risk": "Low", "severity": "info"},
    1026: {"category": "Application Error", "risk": "Low", "severity": "info"},
    1170: {"category": "Application Error", "risk": "Medium", "severity": "medium"},
    # Windows Defender
    1006: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1007: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1008: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1009: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1010: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1011: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1013: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1014: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1015: {"category": "Defender", "risk": "Medium", "severity": "medium"},
    1116: {"category": "Defender Detection", "risk": "High", "severity": "high"},
    1117: {"category": "Defender Protection", "risk": "High", "severity": "high"},
    # Windows Firewall
    2001: {"category": "Firewall", "risk": "Low", "severity": "info"},
    2002: {"category": "Firewall", "risk": "Low", "severity": "info"},
    2003: {"category": "Firewall", "risk": "Medium", "severity": "medium"},
    2004: {"category": "Firewall", "risk": "Low", "severity": "info"},
    5156: {"category": "Firewall", "risk": "Low", "severity": "info"},
    5157: {"category": "Firewall", "risk": "Low", "severity": "info"},
    # Task Scheduler
    106: {"category": "Task Scheduler", "risk": "Medium", "severity": "medium"},
    140: {"category": "Task Scheduler", "risk": "Medium", "severity": "medium"},
    141: {"category": "Task Scheduler", "risk": "Medium", "severity": "medium"},
    200: {"category": "Task Scheduler", "risk": "Low", "severity": "info"},
    201: {"category": "Task Scheduler", "risk": "Low", "severity": "info"},
    202: {"category": "Task Scheduler", "risk": "Low", "severity": "info"},
    325: {"category": "Task Scheduler", "risk": "High", "severity": "high"},
    # Terminal Services / RDP
    21: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    22: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    23: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    24: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    25: {"category": "Remote Desktop", "risk": "Low", "severity": "info"},
    39: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    40: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    41: {"category": "Remote Desktop", "risk": "Low", "severity": "info"},
    261: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    262: {"category": "Remote Desktop", "risk": "Medium", "severity": "low"},
    # WMI Activity
    5856: {"category": "WMI", "risk": "Low", "severity": "info"},
    5857: {"category": "WMI", "risk": "Low", "severity": "info"},
    5860: {"category": "WMI", "risk": "Medium", "severity": "medium"},
    5861: {"category": "WMI", "risk": "Medium", "severity": "medium"},
    # Code Integrity
    3001: {"category": "Code Integrity", "risk": "Medium", "severity": "medium"},
    3002: {"category": "Code Integrity", "risk": "Medium", "severity": "medium"},
    3003: {"category": "Code Integrity", "risk": "Medium", "severity": "medium"},
    3004: {"category": "Code Integrity", "risk": "Medium", "severity": "medium"},
    3033: {"category": "Code Integrity", "risk": "Medium", "severity": "medium"},
    # Driver Frameworks
    2001: {"category": "Driver", "risk": "Low", "severity": "info"},
    2003: {"category": "Driver", "risk": "Low", "severity": "info"},
    2100: {"category": "Driver", "risk": "Low", "severity": "info"},
    2101: {"category": "Driver", "risk": "Low", "severity": "info"},
    2102: {"category": "Driver", "risk": "Low", "severity": "info"},
    # Group Policy
    4004: {"category": "Group Policy", "risk": "Low", "severity": "info"},
    4005: {"category": "Group Policy", "risk": "Low", "severity": "info"},
    4006: {"category": "Group Policy", "risk": "Medium", "severity": "medium"},
    4016: {"category": "Group Policy", "risk": "Medium", "severity": "medium"},
    4017: {"category": "Group Policy", "risk": "Medium", "severity": "medium"},
    # NTLM
    8001: {"category": "NTLM", "risk": "Low", "severity": "info"},
    8002: {"category": "NTLM", "risk": "Low", "severity": "info"},
    # Kerberos (operational)
    # 1000, 1001 already used by Application; Kerberos operational uses same IDs
    # Print Service
    316: {"category": "Print Service", "risk": "High", "severity": "high"},
    808: {"category": "Print Service", "risk": "Medium", "severity": "medium"},
    # AppLocker
    8003: {"category": "AppLocker", "risk": "Medium", "severity": "medium"},
    8004: {"category": "AppLocker", "risk": "Medium", "severity": "medium"},
    8006: {"category": "AppLocker", "risk": "Medium", "severity": "medium"},
    8007: {"category": "AppLocker", "risk": "Medium", "severity": "medium"},
}

MESSAGE_PATTERNS = {
    "account_name": re.compile(r"Account Name:\s+(\S+)", re.IGNORECASE),
    "new_account": re.compile(r"(?:New Account|Account Name):\s+(\S+)", re.IGNORECASE),
    "source_ip": re.compile(r"Source Network Address:\s+(\S+)", re.IGNORECASE),
    "client_ip": re.compile(r"Client Address:\s+(\S+)", re.IGNORECASE),
    "logon_type": re.compile(r"Logon Type:\s+(\d+)", re.IGNORECASE),
    "new_process": re.compile(r"New Process Name:\s+(\S+)", re.IGNORECASE),
    "new_process_id": re.compile(r"NewProcessId:\s+(\S+)", re.IGNORECASE),
    "process_id": re.compile(r"\bProcessId:\s+(\S+)", re.IGNORECASE),
    "parent_process_id": re.compile(r"ParentProcessId:\s+(\S+)", re.IGNORECASE),
    "command_line": re.compile(r"CommandLine:\s+(.+)", re.IGNORECASE),
    "service_name": re.compile(r"Service Name:\s+(\S+)", re.IGNORECASE),
    "service_file": re.compile(r"Service File Name:\s+(\S+)", re.IGNORECASE),
    "task_name": re.compile(r"Task Name:\s+(\S+)", re.IGNORECASE),
    "group_name": re.compile(r"Group:\s+([\w\s-]+?)\.\s+Subject", re.IGNORECASE),
    "target_image": re.compile(r"Target\s*Image:\s+(\S+)", re.IGNORECASE),
    "granted_access": re.compile(r"GrantedAccess:\s+(\S+)", re.IGNORECASE),
    "target_object": re.compile(r"TargetObject:\s+(\S+)", re.IGNORECASE),
    "event_type": re.compile(r"EventType:\s+(\S+)", re.IGNORECASE),
    "details": re.compile(r"Details:\s+(.+)", re.IGNORECASE),
    "target_account_name": re.compile(r"Target Account Name:\s+(\S+)", re.IGNORECASE),
    "deleted_account": re.compile(r"Deleted Account Name:\s+(\S+)", re.IGNORECASE),
    "file_path": re.compile(r"File (?:created|deleted):\s+(\S+)", re.IGNORECASE),
    "ticket_encryption_type": re.compile(r"Ticket Encryption Type:\s+(0x[0-9A-Fa-f]+)", re.IGNORECASE),
    "ticket_options": re.compile(r"Ticket Options:\s+(0x[0-9A-Fa-f]+)", re.IGNORECASE),
    "logon_process": re.compile(r"Logon Process:\s+(\S+)", re.IGNORECASE),
    "authentication_package": re.compile(r"Authentication Package:\s+(\S+)", re.IGNORECASE),
    "workstation_name": re.compile(r"Workstation Name:\s+(\S+)", re.IGNORECASE),
    "access_mask": re.compile(r"Access Mask:\s+(0x[0-9A-Fa-f]+)", re.IGNORECASE),
    "service_sid": re.compile(r"Service SID:\s+(\S+)", re.IGNORECASE),
    "directory_service": re.compile(r"Directory Service:\s+(\S+)", re.IGNORECASE),
    "object_dn": re.compile(r"Object:\s+(\S+)", re.IGNORECASE),
    "source_image": re.compile(r"Source Image:\s+(\S+)", re.IGNORECASE),
    "image": re.compile(r"Image:\s+(\S+)", re.IGNORECASE),
    "image_loaded": re.compile(r"ImageLoaded:\s+(\S+)", re.IGNORECASE),
}


class Normalizer:
    """Converts raw records into normalized event dicts ready for the DB."""

    def __init__(self, hostname: str | None = None):
        import socket
        self.hostname = hostname or socket.gethostname()

    # ------------------------------------------------------------------
    @staticmethod
    def _looks_truncated(value: str, kind: str = "path") -> bool:
        """Heuristic: did the collector / message formatter cut this value short?

        ``kind="path"`` enforces the Windows process-path shape (a full path
        ends in an executable suffix; a bare drive letter or path fragment is
        a truncated copy), ``kind="text"`` only matches explicit truncation
        markers so real text that legitimately ends with a backslash is not
        misread.
        """
        v = str(value or "")
        if not v:
            return False
        if v.endswith(_TRUNCATION_MARKERS) or (kind == "path" and v.endswith("\\")):
            return True
        v = v.strip()
        if not v:
            return True
        if kind == "path":
            lowered = v.lower()
            if not lowered.endswith(_EXEC_SUFFIXES) and ("\\" in v or re.fullmatch(r"[A-Za-z]:?", v)):
                return True
        return False

    @classmethod
    def detect_truncation(cls, record: dict, facts: dict) -> tuple[list[str], list[str]]:
        """Return ``(truncated_fields, reasons)`` describing data-integrity loss.

        Detects three failure modes:

        * the formatted message hit the length cap (collector or DB),
        * a structured process field ends mid-value (explicit truncation
          marker, path fragment with no executable suffix, bare drive letter),
        * a process event carries no structured fields (structured fetch
          failed / message only) so the command line may be lost entirely.
        """
        raw = record.get("raw") or {}
        event_id = int(record.get("event_id") or 0)
        message = str(record.get("message") or "")
        truncated: list[str] = []
        reasons: list[str] = []

        message_cut = len(message) > MAX_MESSAGE_LEN or bool(raw.get("message_truncated"))
        if message_cut:
            truncated.append("message")
            reasons.append(f"formatted message longer than {MAX_MESSAGE_LEN} chars")

        # SafeFormatMessage debris: field values cut to 1-char stubs
        # ("New Process Name: C"). Silent before - the message is short, so
        # the length cap never fired; flag it so repair/quality tracking sees it.
        if message:
            from backend.collectors.validation import is_debris_value

            for line in message.splitlines():
                m = _FIELD_LINE_RE.match(line)
                if not m:
                    continue
                label, value = m.group(1), m.group(2).strip()
                if label in _MESSAGE_LABEL_FACTS and value and is_debris_value(value):
                    truncated.append("message")
                    reasons.append(
                        f"message field '{label}' truncated to debris by the "
                        "message formatter (structured copy used)"
                    )
                    break

        structured = {k: str(facts[k]) for k in _STRUCTURED_PROCESS_KEYS if facts.get(k)}
        if structured:
            for key, value in structured.items():
                kind = "text" if key in ("CommandLine", "ScriptBlockText") else "path"
                if cls._looks_truncated(value, kind):
                    truncated.append(key)
                    reasons.append(f"structured field {key} ends mid-value (truncation marker or partial path)")
        elif event_id in _PROCESS_EVENT_IDS:
            parsed = {
                k: str(v)
                for k, v in facts.items()
                if k in ("new_process", "image", "command_line", "script_block") and v
            }
            if not parsed:
                truncated.append("process_data")
                reasons.append("no process image or command line captured for a process event")
            else:
                for key, value in parsed.items():
                    kind = "text" if key in ("command_line", "script_block") else "path"
                    if cls._looks_truncated(value, kind):
                        truncated.append(key)
                        reasons.append(f"{key} parsed from the message and looks cut short")
                if message_cut or raw.get("structured_fetch_failed"):
                    truncated.append("process_data")
                    reasons.append("message copy only (structured process fields unavailable) - command line may be lost")
        return truncated, reasons

    # ------------------------------------------------------------------
    @staticmethod
    def repair_message(message: str, facts: dict) -> tuple[str, list[str]]:
        """Repair SafeFormatMessage-truncated field values from structured facts.

        The legacy message formatter cuts long values to 1-char debris
        ("New Process Name: C", "Process Command Line: \\\""). When the
        structured XML copy of the field is available it is authoritative
        and wins. Returns ``(repaired_message, repaired_field_labels)``.
        """
        from backend.collectors.validation import is_debris_value

        message = str(message or "")
        if not message or not facts:
            return message, []
        repaired: list[str] = []
        lines = message.splitlines()

        def substitute(line: str) -> str:
            m = _FIELD_LINE_RE.match(line)
            if not m:
                return line
            label, value = m.group(1), m.group(2).strip()
            if not is_debris_value(value):
                return line
            for key in _MESSAGE_LABEL_FACTS.get(label, ()):
                real = facts.get(key)
                if real and not is_debris_value(str(real)):
                    repaired.append(label)
                    return f"{label}: {real}"
            return line

        fixed = "\n".join(substitute(line) for line in lines)
        return (fixed, repaired) if repaired else (message, [])

    # ------------------------------------------------------------------
    @staticmethod
    def _safe_ts(raw_ts: Any) -> datetime:
        if isinstance(raw_ts, datetime):
            return raw_ts
        if isinstance(raw_ts, (int, float)):
            return datetime.fromtimestamp(raw_ts).astimezone()
        if isinstance(raw_ts, str):
            try:
                return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now().astimezone()

    @staticmethod
    def _extract_facts(record: dict) -> dict:
        message = record.get("message", "")
        raw = record.get("raw") or {}
        facts = dict(raw)
        for key, pattern in MESSAGE_PATTERNS.items():
            if key not in facts:
                m = pattern.search(message)
                if m:
                    facts[key] = m.group(1).rstrip(".,;: ")
        return facts

    # ------------------------------------------------------------------
    _ENC_SIGNAL = re.compile(r"(?:enc|encodedcommand|frombase64string|base64)", re.IGNORECASE)
    _DOWNLOAD_SIGNAL = re.compile(
        r"(?:downloadstring|invoke-webrequest|start-bits|webclient|wget|curl|downloadfile)", re.IGNORECASE
    )
    _HIDDEN_SIGNAL = re.compile(r"(?:-w(?:indowstyle)?\s+hidden|/hidden|windowstyle\s+hidden)", re.IGNORECASE)
    _REMOTE_SIGNAL = re.compile(
        r"(?:tcpclient|net\.sockets|\.connect\s*\(|invoke-webrequest|downloadstring|etcp|127\.0\.0\.1)", re.IGNORECASE
    )
    #: System binary names commonly abused by name-masquerading malware.
    _MASQUERADE_NAMES = {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
        "wininit.exe", "spoolsv.exe", "dllhost.exe", "conhost.exe", "taskhost.exe",
        "explorer.exe", "wmiprvse.exe", "searchindexer.exe",
    }
    _SYSTEM32_HINT = re.compile(r"\\windows\\(?:system(?:32|64)\\|syswow64)\\", re.IGNORECASE)

    @classmethod
    def _derive_attack_facts(cls, event_id: int, facts: dict) -> dict:
        """Derive attack-indicator facts from the *real* process/script text.

        The structured event fields (full command line for 4688, script block
        for 4104) are used to populate the same facts the fixtures carry, so
        production telemetry and training fixtures share the exact signal set.
        """
        eid = int(event_id)
        if eid not in (4688, 4104, 4103, 4698, 7045, 4697):
            return facts
        cmd = str(
            facts.get("command_line") or facts.get("CommandLine")
            or facts.get("script_block") or facts.get("ScriptBlockText") or ""
        )
        script = str(
            facts.get("script_block") or facts.get("ScriptBlockText") or ""
        )
        image = str(
            facts.get("image_path") or facts.get("new_process")
            or facts.get("NewProcessName") or ""
        )
        text = (cmd + " " + script).strip()

        # Structured fields are complete; the message-parsed value may be
        # truncated by SafeFormatMessage (e.g. "New Process Name:\tC") - the
        # full structured value is authoritative and must win.
        if facts.get("NewProcessName") and not facts.get("image_path"):
            image = str(facts["NewProcessName"])
            facts["new_process"] = image
        if facts.get("CommandLine"):
            cmd = str(facts["CommandLine"])
            facts["cmdline_len"] = len(cmd)
        if facts.get("ScriptBlockText"):
            script = str(facts["ScriptBlockText"])
            facts["script_len"] = len(script)

        facts.setdefault("cmdline_len", len(cmd))
        if eid in (4104, 4103, 4698):
            facts.setdefault("script_len", len(script))
        if text:
            if not facts.get("has_encoded") and cls._ENC_SIGNAL.search(text):
                facts["has_encoded"] = True
            if not facts.get("has_download") and cls._DOWNLOAD_SIGNAL.search(text):
                facts["has_download"] = True
            if not facts.get("has_remote") and cls._REMOTE_SIGNAL.search(text):
                facts["has_remote"] = True
            if not facts.get("has_hidden") and (cls._HIDDEN_SIGNAL.search(cmd) or cls._is_masquerade(image)):
                facts["has_hidden"] = True
        return facts

    @classmethod
    def _is_masquerade(cls, image: str) -> bool:
        """True when a known-system-name binary runs from a non-system path."""
        if not image:
            return False
        name = image.split("\\")[-1].lower()
        is_system_name = any(
            name == candidate or (candidate.startswith("svchost") and name.startswith("svchost"))
            for candidate in cls._MASQUERADE_NAMES
        )
        if not is_system_name:
            return False
        return not bool(cls._SYSTEM32_HINT.search(image))

    # ------------------------------------------------------------------
    def normalize(self, record: dict) -> dict:
        """Normalize one raw record into a canonical event dict."""
        event_id = int(record.get("event_id") or 0)
        meta = EVENT_META.get(event_id, {"category": "Other", "risk": "Low", "severity": "info"})
        facts = self._extract_facts(record)
        facts = self._derive_attack_facts(event_id, facts)

        # Resolve the user: prefer structured, fall back to message parse.
        user = record.get("user") or facts.get("account_name") or facts.get("new_account") or "-"
        if user in (None, "", "-") and facts.get("new_account"):
            user = facts["new_account"]

        timestamp = self._safe_ts(record.get("timestamp"))

        # Compose a readable one-line message. A stored/forwarded message that
        # is actually Windows' "description could not be found" placeholder
        # (unregistered provider template) is template prose, not telemetry -
        # the composed-from-facts message wins over it.
        raw_message = str(record.get("message") or "")
        if _TEMPLATE_PLACEHOLDER_RE.search(raw_message):
            raw_message = ""
        message = raw_message or self._compose_message(event_id, facts, meta)

        # Data integrity: flag events whose source data was truncated, and
        # surface a clear error so operators can act on the lossy source.
        truncated_fields, truncation_reasons = self.detect_truncation(record, facts)
        if truncated_fields:
            logger.error(
                "Data integrity: event %s (%s) from source '%s' is incomplete - "
                "truncated field(s): %s. Reasons: %s",
                event_id,
                meta["category"],
                record.get("source", "unknown"),
                ", ".join(truncated_fields),
                "; ".join(truncation_reasons),
            )
        data_integrity = "truncated" if truncated_fields else "complete"

        # SafeFormatMessage repair: truncated field values in the message are
        # replaced with the complete structured copy (when available) so the
        # analyst interface never sees "New Process Name: C" debris.
        message, repaired_fields = self.repair_message(message, facts)
        if repaired_fields:
            logger.info(
                "Data integrity: event %s message repaired from structured "
                "fields: %s", event_id, ", ".join(repaired_fields),
            )

        risk_score = RISK_BAND_SCORES.get(meta["risk"], 15)
        risk_score = min(100, risk_score + self._risk_modifiers(event_id, facts))

        return {
            "event_id": event_id,
            "category": meta["category"],
            "risk": meta["risk"],
            "risk_score": float(risk_score),
            "severity": meta["severity"],
            "source": record.get("source", "unknown"),
            "user": str(user)[:128],
            "host": record.get("host") or record.get("raw", {}).get("computer") or self.hostname,
            "message": str(message)[:8192],
            "timestamp": timestamp,
            "data_integrity": data_integrity,
            "raw_json": {
                "facts": {k: v for k, v in facts.items() if isinstance(v, (str, int, float, bool))},
                "channel": record.get("channel", ""),
                "record_number": record.get("raw", {}).get("record_number"),
                "data_integrity": {
                    "complete": not truncated_fields,
                    "truncated_fields": truncated_fields,
                    "repaired_fields": repaired_fields,
                    "reasons": truncation_reasons,
                },
            },
        }

    @staticmethod
    def _risk_modifiers(event_id: int, facts: dict) -> float:
        """Additional risk points for aggravating factors in the event."""
        bonus = 0.0
        if event_id == 4625 and str(facts.get("sub_status", "")) in ("0xC000006D", "0xC0000234"):
            bonus += 10  # locked-account / bad-password attempts
        if event_id in (4720, 4732) and "admin" in str(facts.get("new_account", "")).lower():
            bonus += 10  # admin-named account creation
        if event_id == 4732 and facts.get("group_sid") == "S-1-5-32-544":
            bonus += 15  # Administrators group membership
        if event_id == 7045 and re.search(r"public|temp|downloads", str(facts.get("image_path", "")), re.IGNORECASE):
            bonus += 10  # service binary dropped in user-writable path
        if event_id == 4104 and facts.get("has_encoded"):
            bonus += 15  # encoded PowerShell
        if event_id == 4104 and facts.get("has_download"):
            bonus += 10  # download-execute PowerShell
        if event_id == 4698 and re.search(r"public|temp|downloads", str(facts.get("image_path", "")), re.IGNORECASE):
            bonus += 10
        if event_id == 10 and re.search(r"lsass\.exe$", str(facts.get("target_image", "")), re.IGNORECASE):
            bonus += 20  # LSASS memory access
        if event_id == 13 and re.search(r"\\Run(?:Once)?(?:Services)?\\", str(facts.get("target_object", "")), re.IGNORECASE):
            bonus += 15  # autostart Run-key write
        return bonus

    # ------------------------------------------------------------------
    @staticmethod
    def _compose_message(event_id: int, facts: dict, meta: dict) -> str:
        label = EVENT_META.get(event_id, {}).get("category", "Event")
        bits = [f"Event {event_id} ({label})"]
        if facts.get("new_account"):
            bits.append(f"account={facts['new_account']}")
        if facts.get("account_name"):
            bits.append(f"account={facts['account_name']}")
        if facts.get("source_ip"):
            bits.append(f"source_ip={facts['source_ip']}")
        if facts.get("new_process"):
            bits.append(f"process={facts['new_process']}")
        if facts.get("service_name"):
            bits.append(f"service={facts['service_name']}")
        return " | ".join(bits)

    # ------------------------------------------------------------------
    def normalize_batch(self, records: list[dict]) -> list[dict]:
        return [self.normalize(r) for r in records]
