"""Adapter for Splunk BOTSv1 (Boss of the SOC v1) dataset.

BOTSv1 contains Windows event logs (Security, System, Application),
Sysmon, FortiGate, IIS, Nessus, Stream (DHCP, DNS, HTTP, ICMP, IP,
LDAP, MAPI, SIP, SMB, SNMP, TCP), Suricata, and WinRegistry data
in Splunk JSON format.

Source: https://github.com/splunk/botsv1
"""

from __future__ import annotations

import json
import re
from collections.abc import Generator
from pathlib import Path
from typing import Any

from backend.ml.dataset_adapters.base import (
    BaseAdapter,
    NormalizedEventDict,
    parse_ts,
)

# BOTSv1 Splunk sourcetype → BARAQ channel mapping
_SOURCETYPE_CHANNEL = {
    "WinEventLog:Security": "Security",
    "WinEventLog:System": "System",
    "WinEventLog:Application": "Application",
    "WinEventLog:Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon/Operational",
    "WinEventLog:Windows PowerShell": "Windows PowerShell",
    "WinEventLog:Microsoft-Windows-PowerShell/Operational": "Microsoft-Windows-PowerShell/Operational",
    "WinEventLog:Microsoft-Windows-WFP/_OPERATIONAL": "Microsoft-Windows-WFP/OPERATIONAL",
    "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational": "Microsoft-Windows-Sysmon/Operational",
    "XmlWinEventLog:Security": "Security",
    "xmlwineventlog:microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
    "xmlwineventlog:security": "Security",
}

# BOTSv1 Sysmon event IDs that map to BARAQ event IDs
_SYSMON_MAP = {
    1: 1,  # Process Create
    3: 3,  # Network Connection
    7: 7,  # Image Loaded
    8: 8,  # CreateRemoteThread
    10: 10,  # Process Access
    11: 11,  # File Create
    12: 12,  # Registry Event (Object Create/Delete)
    13: 13,  # Registry Event (Value Set)
    14: 14,  # Registry Event (Object Create/Delete)
    15: 15,  # FileCreateStreamHash
    17: 17,  # Pipe Created
    19: 19,  # WmiEvent
    22: 22,  # DNS Query
}

# BOTSv1 event_name → BARAQ event_id mapping
_EVENT_NAME_MAP = {
    "Logon": 4624,
    "Logoff": 4634,
    "Special Logon": 4672,
    "Account Lockout": 4740,
    "Failed Logon": 4625,
    "Account Created": 4720,
    "Security Group Management": 4732,
    "Audit Log Cleared": 1102,
    "Process Create": 4688,
    "Process Terminate": 4689,
    "File Created": 4663,
    "File Delete": 4660,
    "File Rename": 4663,
    "Pipe Connected": 18,
    "Pipe Created": 17,
    "DNS Query": 22,
    "Network Connection Detected": 3,
    "Connection Attempt": 3,
}

# Attack label patterns (BOTSv1 scenarios)
_ATTACK_INDICATORS = [
    "mimikatz",
    "powershell -enc",
    "invoke-expression",
    "invoke-shellcode",
    "download cradle",
    "certutil -decode",
    "bitsadmin /transfer",
    "mshta http",
    "wscript //e:jscript",
    "reg add.*run",
    "schtasks /create",
    "net user.*add",
    "net localgroup.*add",
    "psexec",
    "lateral",
    "privilege escalation",
    "credential dump",
    "lsass",
    "sekurlsa",
    "kerberos::golden",
    "dcsync",
    "golden ticket",
    "pass the hash",
    "overpass the hash",
]


def _extract_field(event: dict, field: str, fields: dict | None = None) -> Any:
    """Extract a field from Splunk JSON result dict."""
    if fields and field in fields:
        return fields[field]
    return event.get(field)


def _parse_splunk_result(event: dict) -> dict:
    """Parse a Splunk JSON event into a flat dict."""
    result = event.get("result", event)
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (json.JSONDecodeError, TypeError):
            result = {}
    return result if isinstance(result, dict) else {}


def _classify_attack(raw_text: str, cmdline: str = "") -> bool:
    """Check if event text indicates an attack."""
    combined = f"{raw_text} {cmdline}".lower()
    return any(ind in combined for ind in _ATTACK_INDICATORS)


class Botsv1Adapter(BaseAdapter):
    """Adapter for Splunk BOTSv1 dataset (JSON export format)."""

    name = "botsv1"
    description = "Splunk Boss of the SOC v1 — Windows event logs, Sysmon, network, and attack scenarios"

    def iter_events(self, path: Path) -> Generator[dict, None, None]:
        """Yield raw Splunk JSON events from BOTSv1.

        Expects either:
        - A single .json file containing an array of events
        - A directory of .json files (one event per line or arrays)
        - A .jsonl file (one JSON object per line)
        """
        if path.is_file():
            yield from self._read_file(path)
            return

        for file in sorted(path.rglob("*.json")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.jsonl")):
            yield from self._read_file(file)

    def _read_file(self, file: Path) -> Generator[dict, None, None]:
        try:
            content = file.read_text(encoding="utf-8", errors="replace")
            content = content.strip()
            if not content:
                return
            # Try JSON array first
            if content.startswith("["):
                data = json.loads(content)
                yield from data
                return
            # JSONL format
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
        except Exception:
            return

    def parse_event(self, raw: dict) -> NormalizedEventDict | None:
        """Parse a BOTSv1 Splunk JSON event into BARAQ format."""
        result = _parse_splunk_result(raw)
        if not result:
            return None

        # Determine channel/source type
        sourcetype = raw.get("sourcetype", "") or result.get("sourcetype", "")
        channel = _SOURCETYPE_CHANNEL.get(sourcetype, sourcetype)

        # Extract common fields
        host = str(result.get("host", "") or raw.get("host", "") or "")
        user = str(result.get("user", "") or result.get("Account_Name", "") or "")
        timestamp_raw = (
            result.get("_time") or result.get("index_time") or raw.get("time")
        )
        ts = parse_ts(timestamp_raw)
        if ts is None:
            return None

        event_id = int(result.get("EventCode", 0) or result.get("event_id", 0) or 0)
        message = str(result.get("Message", "") or result.get("message", "") or "")
        source_ip = str(
            result.get("IpAddress", "")
            or result.get("SourceIp", "")
            or result.get("src_ip", "")
            or ""
        )

        # Build facts dict for feature extraction
        facts: dict[str, Any] = {}

        # Authentication events
        if event_id in (4624, 4625, 4672, 4740):
            facts["logon_type"] = int(
                result.get("Logon_Type", 0) or result.get("logon_type", 0) or 0
            )
            facts["source_ip"] = source_ip
            facts["target_user"] = user
            facts["sub_status"] = result.get("Sub_Status", result.get("SubStatus", 0))
            facts["is_locked"] = event_id == 4740

        # Sysmon events
        elif event_id in _SYSMON_MAP:
            baraq_id = _SYSMON_MAP[event_id]
            event_id = baraq_id

            if baraq_id == 1:  # Process Create
                facts["image_path"] = result.get(
                    "Image", result.get("NewProcessName", "")
                )
                facts["command_line"] = result.get("CommandLine", "")
                facts["parent_process"] = result.get(
                    "ParentImage", result.get("ParentProcessName", "")
                )
                facts["cmdline_len"] = len(facts.get("command_line", ""))
                facts["has_encoded"] = (
                    1
                    if re.search(
                        r"[A-Za-z0-9+/]{40,}={0,2}", facts.get("command_line", "")
                    )
                    else 0
                )
                facts["has_download"] = (
                    1
                    if any(
                        tok in facts.get("command_line", "").lower()
                        for tok in (
                            "download",
                            "invoke-webrequest",
                            "curl",
                            "wget",
                            "bitsadmin",
                        )
                    )
                    else 0
                )
                facts["has_hidden"] = (
                    1
                    if "-hidden" in facts.get("command_line", "").lower()
                    or "-w hidden" in facts.get("command_line", "").lower()
                    else 0
                )
                facts["has_remote"] = (
                    1
                    if any(
                        tok in facts.get("command_line", "").lower()
                        for tok in ("\\\\", "remote", "psexec", "winrm")
                    )
                    else 0
                )
                facts["script_len"] = len(facts.get("command_line", ""))
                facts["new_process"] = facts["image_path"]

            elif baraq_id == 3:  # Network Connection
                facts["source_ip"] = result.get("SourceIp", result.get("src_ip", ""))
                facts["remote_ip"] = result.get(
                    "DestinationIp", result.get("dst_ip", "")
                )
                facts["remote_port"] = int(
                    result.get("DestinationPort", 0) or result.get("dst_port", 0) or 0
                )
                facts["protocol"] = result.get("Protocol", "")

            elif baraq_id == 10:  # Process Access
                facts["source_image"] = result.get("SourceImage", "")
                facts["target_image"] = result.get("TargetImage", "")
                facts["granted_access"] = result.get("GrantedAccess", "")

            elif baraq_id == 13:  # Registry Value Set
                facts["target_object"] = result.get("TargetObject", "")
                details = result.get("Details", "")
                facts["details"] = details

            elif baraq_id == 22:  # DNS Query
                facts["query"] = result.get("QueryName", "")
                facts["query_status"] = result.get("QueryStatus", "")
                facts["process"] = result.get("Image", "")

        # PowerShell events
        elif event_id in (4104, 4103, 400, 403):
            facts["command_line"] = result.get(
                "ScriptBlockText", result.get("CommandLine", "")
            )
            facts["script_len"] = len(facts.get("command_line", ""))
            facts["cmdline_len"] = len(facts.get("command_line", ""))
            facts["has_encoded"] = (
                1
                if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", facts.get("command_line", ""))
                else 0
            )
            facts["has_download"] = (
                1
                if any(
                    tok in facts.get("command_line", "").lower()
                    for tok in ("downloadstring", "invoke-webrequest", "curl", "wget")
                )
                else 0
            )
            facts["provider"] = result.get("ProviderName", "")

        # WFP network events
        elif event_id in (5156, 5157, 5158):
            facts["source_ip"] = result.get("SourceAddress", "")
            facts["remote_ip"] = result.get("DestinationAddress", "")
            facts["remote_port"] = int(result.get("DestinationPort", 0) or 0)
            facts["protocol"] = result.get("Protocol", "")
            facts["direction"] = result.get("Direction", "")

        # Network stream events (Stream sourcetypes)
        elif sourcetype and "stream:" in sourcetype:
            stream_type = sourcetype.split(":")[-1].lower()
            facts["source_ip"] = result.get("src_ip", result.get("src", ""))
            facts["remote_ip"] = result.get("dest_ip", result.get("dst", ""))
            facts["remote_port"] = int(result.get("dest_port", 0) or 0)
            if stream_type == "dns":
                facts["query"] = result.get("query", "")
            elif stream_type == "http":
                facts["url"] = result.get("url", "")
                facts["http_method"] = result.get("http_method", "")
                facts["status_code"] = result.get("http_status", 0)

        # Suricata events
        elif sourcetype and "suricata" in sourcetype.lower():
            facts["source_ip"] = result.get("src_ip", "")
            facts["remote_ip"] = result.get("dest_ip", "")
            facts["remote_port"] = int(result.get("dest_port", 0) or 0)
            facts["alert_signature"] = result.get("alert_signature", "")
            facts["event_type"] = result.get("event_type", "")

        # Determine attack label from scenario or content
        raw_text = f"{message} {json.dumps(facts)}"
        is_attack = _classify_attack(raw_text, facts.get("command_line", ""))

        # BOTSv1 scenario metadata (if present)
        scenario = raw.get("scenario", "") or result.get("scenario", "")
        if scenario and scenario not in ("", "unknown"):
            is_attack = True

        return NormalizedEventDict(
            event_id=event_id,
            channel=channel,
            timestamp=ts.isoformat(),
            host=host,
            user=user,
            message=message[:1024],
            source_ip=source_ip,
            attack_chain=scenario if scenario else None,
            stage=None,
            source=(
                "process"
                if event_id in (1, 4688, 4689)
                else (
                    "network"
                    if event_id in (3, 5156, 5157, 5158)
                    else (
                        "login"
                        if event_id in (4624, 4625, 4634, 4672, 4740)
                        else "powershell" if event_id in (4104, 4103) else "other"
                    )
                )
            ),
            label=1 if is_attack else 0,
            raw=facts,
        )
