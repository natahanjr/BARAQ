"""Minimal Linux telemetry collector for the SentinelSOC agent.

Used only when the agent runs on a non-Windows host where the Windows
collector stack is unavailable. Emits records in the same schema as the
Windows collectors so the central pipeline can normalise them:

    event_id 4624/4625  -> logon success/failure (from /var/log/auth.log)
    event_id 3          -> network connection        (from `ss`)
    event_id 4688       -> process creation           (from `ps`, diffed)

Diffs are stateful: each collector remembers what it already shipped so the
server receives deltas, not full snapshots, every cycle.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
import time
from datetime import datetime, timezone

logger = logging.getLogger("sentinel.agent.linux")

STATE_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), ".sentinel-agent"
)
os.makedirs(STATE_DIR, exist_ok=True)

_FAILED_SSH = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+"
    r"(?P<time>\d\d:\d\d:\d\d).*Failed password for "
    r"(?:invalid user )?(?P<user>\S+).*from (?P<ip>[\d.]+)"
)
_ACCEPTED_SSH = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+"
    r"(?P<time>\d\d:\d\d:\d\d).*Accepted publickey for "
    r"(?P<user>\S+).*from (?P<ip>[\d.]+)"
)
_SSH_LINE = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+\w+\[(?:\d+)\]:\s+(?P<body>.+)"
)


def _run(cmd: list[str], timeout: int = 15) -> str:
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.stdout + proc.stderr


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_state(name: str) -> set[str]:
    try:
        with open(os.path.join(STATE_DIR, name), encoding="utf-8") as fh:
            return set(line.strip() for line in fh if line.strip())
    except OSError:
        return set()


def _write_state(name: str, keys: set[str]) -> None:
    try:
        with open(os.path.join(STATE_DIR, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(keys)))
    except OSError:
        pass


def _tail_authlog(path: str, window: int = 600) -> list[str]:
    """Return recent auth.log lines (last `window` seconds by timestamp)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, size - 4 * 1024 * 1024))
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    now = datetime.now().astimezone().replace(second=0, microsecond=0)
    lines = []
    for raw in text.splitlines():
        m = _SSH_LINE.match(raw)
        if not m:
            continue
        try:
            ts = datetime.strptime(
                f"{now.year} {m.group('month')} {m.group('day')} {m.group('time')}",
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
        if (now - ts).total_seconds() <= window:
            lines.append(raw)
    return lines


def collect_auth() -> list[dict]:
    records = []
    path = os.environ.get("SENTINEL_AUTH_LOG", "/var/log/auth.log")
    for line in _tail_authlog(path):
        m = _FAILED_SSH.search(line)
        if m:
            records.append({
                "source": "linux-auth",
                "event_id": 4625,
                "timestamp": _now_iso(),
                "category": "login",
                "action": "logon_failure",
                "message": f"Failed SSH login for {m.group('user')} from {m.group('ip')}",
                "severity": 4,
                "user": {"name": m.group("user")},
                "network": {"source_ip": m.group("ip")},
                "logon": {"type": 3, "sub_status": "0xC000006A"},
            })
            continue
        m = _ACCEPTED_SSH.search(line)
        if m:
            records.append({
                "source": "linux-auth",
                "event_id": 4624,
                "timestamp": _now_iso(),
                "category": "login",
                "action": "logon_success",
                "message": f"Accepted SSH login for {m.group('user')} from {m.group('ip')}",
                "severity": 1,
                "user": {"name": m.group("user")},
                "network": {"source_ip": m.group("ip")},
                "logon": {"type": 3},
            })
    return records


def collect_connections() -> list[dict]:
    out = _run(["ss", "-tunap"])
    seen: set[str] = set()
    now = _now_iso()
    records = []
    for raw in out.splitlines()[1:]:
        parts = raw.split()
        if len(parts) < 5:
            continue
        state = parts[0]
        if state not in ("ESTAB", "SYN-SENT", "TIME-WAIT"):
            continue
        try:
            local, remote = parts[3], parts[4]
        except IndexError:
            continue
        lhost, _, lport = local.rpartition(":")
        rhost, _, rport = remote.rpartition(":")
        if rhost in ("0.0.0.0", "::", "*"):
            continue
        proc = ""
        if len(parts) > 5 and "users:" in parts[5]:
            proc = parts[5]
        key = f"{lhost}:{lport}-{rhost}:{rport}-{proc}"
        if key in seen:
            continue
        seen.add(key)
        records.append({
            "source": "linux-conn",
            "event_id": 3,
            "timestamp": now,
            "category": "network",
            "action": "connect",
            "message": f"Connection {lhost}:{lport} -> {rhost}:{rport}",
            "severity": 2,
            "network": {
                "local_ip": lhost, "local_port": lport,
                "remote_ip": rhost, "remote_port": rport,
            },
            "process": {"name": proc},
        })
    return records


def collect_processes() -> list[dict]:
    state = _read_state("procs.txt")
    out = _run(["ps", "-eo", "pid=,ppid=,comm=,args="])
    current: set[str] = set()
    records = []
    now = _now_iso()
    for raw in out.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split(None, 3)
        if len(parts) < 4:
            continue
        pid, ppid, comm, args = parts
        if comm in ("ps", "ss"):
            continue
        key = f"{pid}::{comm}"
        current.add(key)
        if key not in state:
            records.append({
                "source": "linux-proc",
                "event_id": 4688,
                "timestamp": now,
                "category": "process",
                "action": "process_launch",
                "message": f"New process {comm} (pid {pid})",
                "severity": 2,
                "process": {
                    "name": comm, "pid": int(pid), "parent_pid": int(ppid),
                    "command_line": args,
                },
            })
    if not state:
        # First run: prime the baseline silently so the server receives
        # only genuine new processes, not the entire process table.
        _write_state("procs.txt", current)
        return []
    _write_state("procs.txt", current)
    return records


def collect() -> list[dict]:
    records: list[dict] = []
    for fn in (collect_auth, collect_connections, collect_processes):
        try:
            records.extend(fn())
        except Exception as exc:  # noqa: BLE001 - one collector must not kill the agent
            logger.warning("Linux collector %s failed: %s", fn.__name__, exc)
    return records