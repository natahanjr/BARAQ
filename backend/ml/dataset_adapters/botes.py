"""Adapter for BOTES (Boss of the Elastic SOC) dataset.

BOTES is a cleaned, ECS-formatted version of BOTSv1 for the Elastic
Stack.  Events follow the Elastic Common Schema (ECS) with fields
like ``event.code``, ``user.name``, ``source.ip``, ``process.command_line``,
etc.

Source: https://github.com/Seblhd/BOTES
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

# ECS event.category → BARAQ channel mapping
_ECS_CATEGORY_CHANNEL = {
    "authentication": "Security",
    "process": "Microsoft-Windows-Sysmon/Operational",
    "network": "Microsoft-Windows-WFP/OPERATIONAL",
    "file": "Microsoft-Windows-Sysmon/Operational",
    "registry": "Microsoft-Windows-Sysmon/Operational",
    "dns": "Microsoft-Windows-Sysmon/Operational",
    "http": "Microsoft-Windows-WFP/OPERATIONAL",
    "powershell": "Microsoft-Windows-PowerShell/Operational",
    "driver": "Microsoft-Windows-Sysmon/Operational",
    "library": "Microsoft-Windows-Sysmon/Operational",
    "module": "Microsoft-Windows-Sysmon/Operational",
}

# ECS event.code → BARAQ event_id mapping
_ECS_CODE_MAP = {
    # Authentication
    "4624": 4624,
    "4625": 4625,
    "4634": 4634,
    "4647": 4647,
    "4648": 4648,
    "4672": 4672,
    "4740": 4740,
    "4771": 4771,
    "4776": 4776,
    "4720": 4720,
    "4732": 4732,
    # Sysmon
    "1": 1,
    "3": 3,
    "7": 7,
    "8": 8,
    "10": 10,
    "11": 11,
    "12": 12,
    "13": 13,
    "14": 14,
    "15": 15,
    "17": 17,
    "19": 19,
    "22": 22,
    # Sysmon via ECS event.code (strings)
    "process_create": 1,
    "network_connection": 3,
    "file_create": 11,
    "registry_value_set": 13,
    "dns_query": 22,
    "process_access": 10,
    # PowerShell
    "4104": 4104,
    "4103": 4103,
    "400": 400,
    "403": 403,
    # WFP
    "5156": 5156,
    "5157": 5157,
    "5158": 5158,
}

# ECS event.outcome → attack label
_OUTCOME_ATTACK = {"failure"}
_OUTCOME_BENIGN = {"success", "unknown"}

# ECS event.type → BARAQ event stream
_TYPE_STREAM = {
    "start": "login",
    "end": "login",
    "info": "other",
    "creation": "process",
    "change": "process",
    "deletion": "process",
    "access": "process",
    "connection": "network",
    "denied": "network",
    "protocol": "network",
}

# ECS process.name → BARAQ source classification
_SUSPICIOUS_PROCESSES = {
    "mimikatz",
    "procdump",
    "psexec",
    "nc",
    "ncat",
    "netcat",
    "certutil",
    "mshta",
    "wscript",
    "cscript",
    "bitsadmin",
    "rundll32",
    "regsvr32",
    "msiexec",
    "installutil",
}


def _ecs_attack_indicators(event: dict) -> bool:
    """Check ECS event fields for attack indicators."""
    # Check process.name for suspicious tools
    proc_name = str(event.get("process", {}).get("name", "") or "").lower()
    if proc_name in _SUSPICIOUS_PROCESSES:
        return True

    # Check process.command_line for suspicious patterns
    cmdline = str(event.get("process", {}).get("command_line", "") or "").lower()
    suspicious_patterns = [
        "mimikatz",
        "invoke-expression",
        "invoke-shellcode",
        "downloadstring",
        "certutil -decode",
        "bitsadmin /transfer",
        "mshta http",
        "-hidden",
        "-nop -w hidden",
        "reg add.*run",
        "schtasks /create",
        "sekurlsa",
        "kerberos::golden",
        "dcsync",
        "psexec",
        "overpass the hash",
        "pass the hash",
    ]
    if any(pat in cmdline for pat in suspicious_patterns):
        return True

    # Check ECS rule for attack detection
    rule_name = str(event.get("rule", {}).get("name", "") or "").lower()
    if any(
        kw in rule_name
        for kw in ("attack", "threat", "malicious", "exploit", "suspicious")
    ):
        return True

    # Check ECS threat indicators
    threat = event.get("threat", {})
    if threat.get("indicator", {}).get("type"):
        return True

    # Check ECS event.outcome for authentication failures
    outcome = str(event.get("event", {}).get("outcome", "") or "").lower()
    if outcome == "failure":
        # Failed auth is only attack if from external IP or unusual pattern
        src_ip = str(event.get("source", {}).get("ip", "") or "")
        if src_ip and not _is_private_ip(src_ip):
            return True

    return False


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP is RFC1918/loopback."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


class BotesAdapter(BaseAdapter):
    """Adapter for BOTES (ECS-formatted BOTS) dataset."""

    name = "botes"
    description = "Boss of the Elastic SOC — ECS-formatted BOTSv1 for Elastic Stack"

    def iter_events(self, path: Path) -> Generator[dict, None, None]:
        """Yield raw ECS events from BOTES.

        Expects .json files with arrays or one JSON object per line,
        or .ndjson / .jsonl files.
        """
        if path.is_file():
            yield from self._read_file(path)
            return

        for file in sorted(path.rglob("*.json")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.jsonl")):
            yield from self._read_file(file)
        for file in sorted(path.rglob("*.ndjson")):
            yield from self._read_file(file)

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

    def parse_event(self, raw: dict) -> NormalizedEventDict | None:
        """Parse an ECS event into BARAQ format."""
        event = raw.get("_source", raw)
        if not isinstance(event, dict):
            return None

        # Extract ECS fields with safe defaults
        ecs = event  # ECS fields are at top level in _source
        event_code = str(ecs.get("event", {}).get("code", "") or "")
        event_category = str(ecs.get("event", {}).get("category", "") or "")
        event_type = str(ecs.get("event", {}).get("type", "") or "")

        # Timestamp
        ts_raw = ecs.get("@timestamp") or ecs.get("event", {}).get("created")
        ts = parse_ts(ts_raw)
        if ts is None:
            return None

        # Host
        host = str(ecs.get("host", {}).get("name", "") or "")

        # User
        user = str(ecs.get("user", {}).get("name", "") or "")

        # Source IP
        source_ip = str(
            ecs.get("source", {}).get("ip", "")
            or ecs.get("client", {}).get("ip", "")
            or ""
        )

        # Map ECS event.code to BARAQ event_id
        baraq_event_id = _ECS_CODE_MAP.get(event_code, 0)

        # If no numeric code, try event.action or event.category
        if not baraq_event_id:
            event_action = str(ecs.get("event", {}).get("action", "") or "")
            baraq_event_id = _ECS_CODE_MAP.get(event_action, 0)

        # Determine channel from ECS category
        channel = _ECS_CATEGORY_CHANNEL.get(event_category, f"ECS:{event_category}")

        # Determine source stream
        source_stream = _TYPE_STREAM.get(event_type, "other")

        # Build facts dict
        facts: dict[str, Any] = {}

        # Process fields (ECS)
        process = ecs.get("process", {})
        if process:
            facts["image_path"] = str(
                process.get("executable", "") or process.get("name", "")
            )
            facts["command_line"] = str(process.get("command_line", "") or "")
            facts["parent_process"] = str(
                process.get("parent", {}).get("name", "")
                or process.get("parent", {}).get("executable", "")
            )
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
                1 if "-hidden" in cmdline or "-w hidden" in cmdline else 0
            )
            facts["has_remote"] = (
                1
                if any(tok in cmdline for tok in ("\\\\", "remote", "psexec", "winrm"))
                else 0
            )
            facts["script_len"] = len(facts["command_line"])
            facts["new_process"] = facts["image_path"]
            facts["pid"] = process.get("pid", 0)

        # Network fields (ECS)
        network = ecs.get("network", {})
        if network:
            facts["protocol"] = str(network.get("transport", "") or "")
            facts["bytes_sent"] = network.get("bytes", 0)
            facts["bytes_recv"] = network.get("bytes", 0)

        # DNS fields (ECS)
        dns = ecs.get("dns", {})
        if dns:
            facts["query"] = str(dns.get("question", {}).get("name", "") or "")
            facts["query_type"] = str(dns.get("question", {}).get("type", "") or "")
            answers = dns.get("answers", [])
            if answers and isinstance(answers, list):
                facts["response"] = str(answers[0].get("data", "") or "")

        # HTTP fields (ECS)
        http = ecs.get("http", {})
        if http:
            request = http.get("request", {})
            response = http.get("response", {})
            facts["url"] = str(request.get("url", "") or "")
            facts["http_method"] = str(request.get("method", "") or "")
            facts["status_code"] = int(response.get("status_code", 0) or 0)

        # Registry fields (ECS)
        registry = ecs.get("registry", {})
        if registry:
            facts["target_object"] = str(registry.get("path", "") or "")
            facts["details"] = str(registry.get("data", {}).get("strings", "") or "")

        # File fields (ECS)
        file_data = ecs.get("file", {})
        if file_data:
            facts["file_path"] = str(file_data.get("path", "") or "")
            facts["file_name"] = str(file_data.get("name", "") or "")

        # Authentication fields (ECS)
        if event_category == "authentication":
            logon_type = ecs.get("winlog", {}).get("logon", {}).get("type", 0)
            facts["logon_type"] = int(logon_type or 0)
            facts["source_ip"] = source_ip
            facts["target_user"] = user
            facts["is_locked"] = event_code == "4740"
            # Sub-status from winlog
            sub_status = ecs.get("winlog", {}).get("event_data", {}).get("SubStatus", 0)
            facts["sub_status"] = sub_status

        # Determine message
        message = str(
            ecs.get("message", "") or ecs.get("event", {}).get("original", "") or ""
        )

        # Determine attack label
        is_attack = _ecs_attack_indicators(event)
        # Override with explicit rule match
        rule_tags = ecs.get("rule", {}).get("tags", [])
        if isinstance(rule_tags, list):
            for tag in rule_tags:
                if "attack" in str(tag).lower():
                    is_attack = True
                    break

        # MITRE info is available via rule.tags but not stored per-event

        return NormalizedEventDict(
            event_id=baraq_event_id,
            channel=channel,
            timestamp=ts.isoformat(),
            host=host,
            user=user,
            message=message[:1024],
            source_ip=source_ip,
            attack_chain=None,
            stage=None,
            source=source_stream,
            label=1 if is_attack else 0,
            raw=facts,
        )
