"""Adapter for OTRF Security-Datasets.

OTRF Security-Datasets provides pre-labeled attack and benign datasets
for security research.  Data is in JSON (Zeek/OCSF) or CSV format
with MITRE ATT&CK mappings.

Source: https://github.com/OTRF/Security-Datasets
"""

from __future__ import annotations

import ipaddress
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


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


# OCSF event categories → BARAQ event stream
_OCSF_CATEGORY_MAP = {
    "security_finding": "other",
    "authentication": "login",
    "network_activity": "network",
    "process_activity": "process",
    "file_activity": "process",
    "registry_activity": "process",
    "dns_activity": "network",
    "http_activity": "network",
    "iam": "login",
    "schedule": "process",
    "base": "other",
}

# OCSF class_name → BARAQ event_id mapping
_OCSF_CLASS_MAP = {
    "Authentication": 4624,
    "Account Logon": 4624,
    "Failed Logon": 4625,
    "Account Lockout": 4740,
    "Account Creation": 4720,
    "Account Modification": 4732,
    "Logoff": 4634,
    "Special Logon": 4672,
    "Process Creation": 1,
    "Network Connection": 3,
    "File Creation": 11,
    "Registry Modification": 13,
    "DNS Query": 22,
    "HTTP Request": 0,
    "Module Load": 7,
    "Raw Access": 10,
    "Pipe Created": 17,
    "WMI Event": 19,
    "Screenshot": 0,
}

# OTRF attack scenario → BARAQ label
_ATTACK_SCENARIOS = {
    "credential_access",
    "lateral_movement",
    "privilege_escalation",
    "execution",
    "persistence",
    "defense_evasion",
    "discovery",
    "collection",
    "exfiltration",
    "command_and_control",
    "initial_access",
    "impact",
    "reconnaissance",
    "resource_development",
}


class SecurityDatasetsAdapter(BaseAdapter):
    """Adapter for OTRF Security-Datasets (JSON/CSV format)."""

    name = "security_datasets"
    description = "OTRF Security-Datasets — pre-labeled attack/benign datasets with MITRE mappings"

    def iter_events(self, path: Path) -> Generator[dict, None, None]:
        """Yield raw events from Security-Datasets.

        Supports JSON (OCSF), CSV, and directory-of-files formats.
        """
        if path.is_file():
            yield from self._read_file(path)
            return

        for file in sorted(path.rglob("*.json")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.jsonl")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.log")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.csv")):
            yield from self._read_csv(file)

    def _read_file(self, file: Path) -> Generator[dict, None, None]:
        try:
            content = file.read_text(encoding="utf-8", errors="replace")
            content = content.strip()
            if not content:
                return
            if content.startswith("["):
                data = json.loads(content)
                for item in data:
                    if isinstance(item, dict):
                        yield item
                return
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        yield obj
                except json.JSONDecodeError:
                    continue
        except Exception:
            return

    def _read_csv(self, file: Path) -> Generator[dict, None, None]:
        try:
            import csv

            with open(file, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row:
                        yield dict(row)
        except Exception:
            return

    def parse_event(self, raw: dict) -> NormalizedEventDict | None:
        """Parse a Security-Datasets event into BARAQ format."""
        if not isinstance(raw, dict):
            return None
        # Handle both OCSF format and raw format
        event = raw
        if "_source" in raw:
            event = raw["_source"]

        # OCSF fields
        activity_id = int(event.get("activity_id", 0) or 0)
        category_uid = int(event.get("category_uid", 0) or 0)
        class_uid = int(event.get("class_uid", 0) or 0)
        class_name = str(event.get("class_name", "") or "")
        category_name = str(
            event.get("category_name", "") or event.get("category", "") or ""
        )

        # Timestamp
        ts_raw = event.get("time") or event.get("@timestamp") or event.get("timestamp")
        ts = parse_ts(ts_raw)
        if ts is None:
            return None

        # Host
        host_raw = event.get("host", "")
        if isinstance(host_raw, dict):
            host = str(host_raw.get("name", "") or "")
        else:
            host = str(
                host_raw
                or event.get("hostname", "")
                or event.get("host_name", "")
                or ""
            )

        # User
        user_raw = event.get("user", "")
        if isinstance(user_raw, dict):
            user = str(user_raw.get("name", "") or "")
        else:
            user = str(
                user_raw
                or event.get("username", "")
                or event.get("user_name", "")
                or event.get("TargetUserName", "")
                or ""
            )

        # Source IP
        source_raw = event.get("source", "")
        if isinstance(source_raw, dict):
            source_ip = str(source_raw.get("ip", "") or "")
        else:
            source_ip = str(
                source_raw
                or event.get("src_ip", "")
                or event.get("SourceIp", "")
                or event.get("SourceAddress", "")
                or event.get("IpAddress", "")
                or ""
            )

        # Destination IP
        dest_raw = event.get("destination", "")
        if isinstance(dest_raw, dict):
            dest_ip = str(dest_raw.get("ip", "") or "")
        else:
            dest_ip = str(
                dest_raw
                or event.get("dst_ip", "")
                or event.get("DestinationIp", "")
                or event.get("DestAddress", "")
                or ""
            )

        # Determine BARAQ event_id
        baraq_event_id = _OCSF_CLASS_MAP.get(class_name, 0)

        # Try mapping from class_uid if class_name not found
        if not baraq_event_id and class_uid:
            if category_uid == 1:
                if activity_id == 1:
                    baraq_event_id = 1
                elif activity_id == 2:
                    baraq_event_id = 3
                elif activity_id == 3:
                    baraq_event_id = 13
            elif category_uid == 2:
                if activity_id == 1:
                    baraq_event_id = 4624
                elif activity_id == 2:
                    baraq_event_id = 4625
            elif category_uid == 3:
                baraq_event_id = (
                    3 if activity_id == 1 else 22 if activity_id == 2 else 0
                )

        # Raw Windows Event Log format (Mordor/Sysmon) — use EventID directly
        if not baraq_event_id:
            raw_eid = int(event.get("EventID", 0) or 0)
            if raw_eid:
                baraq_event_id = raw_eid

        # Channel from category, or raw Channel field
        raw_channel = str(event.get("Channel", "") or "")
        if category_name:
            channel = _OCSF_CATEGORY_MAP.get(
                category_name.lower().replace(" ", "_"), raw_channel or f"OCSF:{category_name}"
            )
        elif raw_channel:
            channel = raw_channel
        else:
            channel = "other"

        # Source stream
        if category_name:
            source_stream = _OCSF_CATEGORY_MAP.get(
                category_name.lower().replace(" ", "_"), "other"
            )
        elif raw_channel:
            _rc = raw_channel.lower()
            if "security" in _rc:
                source_stream = "login"
            elif "sysmon" in _rc or "process" in _rc:
                source_stream = "process"
            else:
                source_stream = "other"
        else:
            source_stream = "other"

        # Build facts dict
        facts: dict[str, Any] = {}
        facts["source_ip"] = source_ip

        # Authentication fields (OCSF + raw Windows Security events)
        if baraq_event_id in (4624, 4625, 4672, 4740, 4634, 4647, 4648):
            facts["logon_type"] = int(
                event.get("logon_type", 0) or event.get("LogonType", 0) or 0
            )
            facts["source_ip"] = source_ip
            facts["target_user"] = user
            facts["sub_status"] = int(event.get("Sub_Status", event.get("sub_status", 0)) or 0)
            facts["is_locked"] = baraq_event_id == 4740
            # Parse raw Message for Sub_Status / LogonType if zero
            if not facts["logon_type"] or not facts["sub_status"]:
                msg = str(event.get("Message", "") or "")
                if "Logon Type:" in msg:
                    m = re.search(r"Logon Type:\s*(\d+)", msg)
                    if m:
                        facts["logon_type"] = int(m.group(1))
                if "Sub Status:" in msg:
                    m = re.search(r"Sub Status:\s*(0x[\da-fA-F]+)", msg)
                    if m:
                        facts["sub_status"] = int(m.group(1), 16)
                # Also grab TargetUserName from Message
                if not user and "TargetUserName:" in msg:
                    m = re.search(r"TargetUserName:\s*(\S+)", msg)
                    if m:
                        facts["target_user"] = m.group(1)
                        user = m.group(1)
                # SourceNetworkAddress from Message
                if "Source Network Address:" in msg:
                    m = re.search(r"Source Network Address:\s*(\S+)", msg)
                    if m and m.group(1) != "-":
                        facts["source_ip"] = m.group(1)
                        source_ip = m.group(1)

        # Process fields
        if baraq_event_id in (1, 10, 11, 13, 17, 19, 7, 23, 25, 8):
            process = event.get("process", {})
            if isinstance(process, dict) and process:
                facts["image_path"] = str(
                    process.get("executable", "") or process.get("name", "") or ""
                )
                facts["command_line"] = str(process.get("command_line", "") or "")
                facts["parent_process"] = str(
                    process.get("parent_process", "")
                    or process.get("ParentImage", "")
                    or ""
                )
                parent_raw = process.get("parent", {})
                if isinstance(parent_raw, dict) and parent_raw.get("name"):
                    facts["parent_process"] = str(parent_raw["name"])
            else:
                facts["image_path"] = str(
                    event.get("Image", "")
                    or event.get("SourceImage", "")
                    or event.get("NewProcessName", "")
                    or event.get("TargetImage", "")
                    or ""
                )
                facts["command_line"] = str(
                    event.get("CommandLine", "")
                    or event.get("ProcessCommandLine", "")
                    or ""
                )
                facts["parent_process"] = str(
                    event.get("ParentImage", "")
                    or event.get("ParentProcessName", "")
                    or ""
                )
                # Sysmon Process Access (EventID 10)
                if baraq_event_id == 10:
                    facts["target_image"] = str(event.get("TargetImage", "") or "")
                    facts["granted_access"] = str(event.get("GrantedAccess", "") or "")
                    facts["call_trace"] = str(event.get("CallTrace", "") or "")[:500]

            facts["cmdline_len"] = len(facts.get("command_line", ""))
            cmdline = facts["command_line"].lower()
            facts["has_encoded"] = (
                1
                if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", facts["command_line"])
                else 0
            )
            facts["has_download"] = (
                1
                if any(
                    tok in cmdline
                    for tok in ("download", "invoke-webrequest", "curl", "wget")
                )
                else 0
            )
            facts["has_hidden"] = (
                1 if "-hidden" in cmdline or "-w hidden" in cmdline else 0
            )
            facts["has_remote"] = (
                1 if any(tok in cmdline for tok in ("\\\\", "remote", "psexec")) else 0
            )
            facts["script_len"] = len(facts["command_line"])
            facts["new_process"] = facts["image_path"]

            # Registry-specific
            if baraq_event_id == 13:
                facts["target_object"] = str(
                    event.get("target_object", "") or event.get("ObjectName", "") or ""
                )
                facts["details"] = str(event.get("details", "") or "")

        # Network fields
        if baraq_event_id in (3, 5156, 5157, 5158):
            network = event.get("network", {})
            facts["source_ip"] = source_ip
            facts["remote_ip"] = dest_ip
            dest_port_raw = event.get("destination", {})
            if isinstance(dest_port_raw, dict):
                facts["remote_port"] = int(dest_port_raw.get("port", 0) or 0)
            else:
                facts["remote_port"] = int(
                    event.get("DestinationPort", 0) or event.get("DestPort", 0) or 0
                )
            if isinstance(network, dict):
                facts["protocol"] = str(network.get("transport", "") or "")
                facts["bytes_sent"] = network.get("bytes", 0)
                facts["bytes_recv"] = network.get("bytes", 0)
            else:
                facts["protocol"] = str(event.get("Protocol", "") or "")

        # DNS fields
        if class_name == "DNS Query" or "dns" in category_name.lower():
            dns_raw = event.get("dns", {})
            if isinstance(dns_raw, dict):
                question = dns_raw.get("question", {})
                if isinstance(question, dict):
                    facts["query"] = str(question.get("name", "") or "")
                else:
                    facts["query"] = str(dns_raw.get("query_name", "") or "")
            else:
                facts["query"] = str(
                    event.get("query_name", "") or event.get("QueryName", "") or ""
                )

        # HTTP fields
        if class_name == "HTTP Request" or "http" in category_name.lower():
            http = event.get("http", {})
            if isinstance(http, dict):
                request = http.get("request", {})
                response = http.get("response", {})
                if isinstance(request, dict):
                    facts["url"] = str(request.get("url", "") or "")
                    facts["http_method"] = str(request.get("method", "") or "")
                if isinstance(response, dict):
                    facts["status_code"] = int(response.get("status_code", 0) or 0)
                facts["status_code"] = int(
                    http.get("response", {}).get("status_code", 0) or 0
                )

        # Message
        log_raw = event.get("log", {})
        if isinstance(log_raw, dict):
            message = str(event.get("message", "") or log_raw.get("message", "") or "")
        else:
            message = str(event.get("message", "") or "")

        # Attack label from scenario or MITRE mapping
        attack_raw = event.get("attack", {})
        if isinstance(attack_raw, dict):
            scenario = str(
                event.get("scenario", "") or attack_raw.get("scenario", "") or ""
            ).lower()
            mitre_id = str(
                attack_raw.get("technique_id", "")
                or event.get("mitre_technique", "")
                or ""
            )
        else:
            scenario = str(event.get("scenario", "") or "").lower()
            mitre_id = str(event.get("mitre_technique", "") or "")

        is_attack = bool(
            scenario in _ATTACK_SCENARIOS
            or (mitre_id and mitre_id.startswith("T"))
            or activity_id
            in (2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)  # Non-benign activity IDs
        )

        # Explicit label field if present
        if "label" in event:
            label_val = event["label"]
            if isinstance(label_val, str):
                is_attack = label_val.lower() in (
                    "attack",
                    "malicious",
                    "1",
                    "true",
                    "suspicious",
                )
            else:
                is_attack = bool(label_val)

        return NormalizedEventDict(
            event_id=baraq_event_id,
            channel=channel,
            timestamp=ts.isoformat(),
            host=host,
            user=user,
            message=message[:1024],
            source_ip=source_ip,
            attack_chain=scenario if scenario else None,
            stage=scenario if scenario else None,
            source=source_stream,
            label=1 if is_attack else 0,
            raw=facts,
        )
