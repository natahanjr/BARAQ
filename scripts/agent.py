"""SentinelSOC remote agent - collect and ship telemetry to a central server.

Run on any Windows host (including the server itself) to form a 2-3 host
fleet:

    python scripts/agent.py --server http://central:8000 --key <agent-key> --interval 15

The agent runs the same collector set as the server, stamps every record
with the local hostname, and POSTs it to ``POST /api/ingest``. The server
validates the ``X-Agent-Key`` header, attributes the records to the agent,
and runs the full detection pipeline centrally.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import time
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s")
logger = logging.getLogger("sentinel.agent")


def _request(base: str, path: str, key: str, payload: dict | None = None, method: str = "GET") -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Agent-Key": key},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _run(cmd: list[str]) -> tuple[str, int]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return (proc.stdout + proc.stderr).strip(), proc.returncode


def execute_command(cmd: dict) -> dict:
    """Execute one remote command locally; returns the result report dict."""
    action, target = cmd.get("action", ""), cmd.get("target", "")
    if action == "block_ip":
        out, code = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                          f"name=SentinelSOC Block {target}", "dir=in", "action=block",
                          f"remoteip={target}", "enable=yes"])
        if code != 0:
            out, code = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                              f"name=SentinelSOC Block {target}", "dir=out", "action=block",
                              f"remoteip={target}", "enable=yes"])
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "kill_process":
        out, code = _run(["powershell", "-NoProfile", "-Command",
                          f"Get-Process -Name {target} -ErrorAction SilentlyContinue | Stop-Process -Force"])
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "quarantine":
        q = os.path.join(os.environ.get("SystemDrive", "C:"), "SentinelSOC-Quarantine")
        out, code = _run(["powershell", "-NoProfile", "-Command",
                          f"if (-not (Test-Path '{q}')) {{ New-Item -ItemType Directory -Path '{q}' | Out-Null }}; "
                          f"Move-Item -LiteralPath '{target}' -Destination '{q}' -Force"])
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "isolate":
        out, code = _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        if code == 0:
            out, code = _run(["powershell", "-NoProfile", "-Command",
                              f"New-NetFirewallRule -DisplayName 'SentinelSOC Isolate {target}' -Direction Inbound -Action Block -Profile Any | Out-Null; "
                              f"New-NetFirewallRule -DisplayName 'SentinelSOC Isolate {target} Out' -Direction Outbound -Action Block -Profile Any | Out-Null"])
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "disable_account":
        out, code = _run(["powershell", "-NoProfile", "-Command",
                          f"Disable-LocalUser -Name '{target}' -ErrorAction Stop"])
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "escalate":
        logger.warning("Operator escalated agent %s - manual review required", cmd.get("agent_id"))
        return {"status": "success", "detail": "Acknowledged by operator"}
    return {"status": "failed", "detail": f"Unknown action: {action}"}


def collect() -> list[dict]:
    from backend.collectors import CollectorManager

    host = socket.gethostname()
    records = []
    for record in CollectorManager().collect():
        record["host"] = host
        records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="SentinelSOC remote telemetry agent")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Central SentinelSOC API")
    parser.add_argument("--key", default="sentinel-agent-dev", help="Agent key (X-Agent-Key)")
    parser.add_argument("--interval", type=int, default=15, help="Collection interval (seconds)")
    args = parser.parse_args()

    host = socket.gethostname()
    logger.info("SentinelSOC agent starting (host=%s, server=%s)", host, args.server)
    while True:
        try:
            try:
                pending = _request(args.server, "/api/commands/pending", args.key)
                for cmd in pending.get("items", []):
                    report = execute_command(cmd)
                    try:
                        _request(args.server, f"/api/commands/{cmd['id']}/result",
                                 args.key, report, method="POST")
                        logger.info("Command #%s (%s %s) -> %s", cmd["id"], cmd["action"], cmd["target"], report["status"])
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("Failed to report command #%s: %s", cmd.get("id"), exc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Command poll failed: %s", exc)

            records = collect()
            if records:
                result = _request(
                    args.server,
                    "/api/ingest",
                    args.key,
                    {"records": records, "host": host},
                    method="POST",
                )
                logger.info(
                    "Shipped %d records -> %s alerts",
                    result.get("collected", 0), result.get("alerts_created", 0),
                )
            else:
                logger.debug("No records collected")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Agent cycle failed: %s", exc)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()