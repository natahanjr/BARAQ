"""BARAQ remote agent - collect and ship telemetry to a central server.

Run on any Windows host (including the server itself) to form a 2-3 host
fleet:

    python scripts/agent.py --server https://central:8443 --key <agent-key> --interval 15
    python scripts/agent.py --server https://central:8443 --key <agent-key> --tls-ca certs/baraq.crt

HTTPS is the standard transport for fleet deployments: the server's
self-signed certificate (certs/baraq.crt) can be pinned on the agent with
``--tls-ca`` so connections are verified end-to-end. ``--no-verify`` exists
for lab use only and logs a warning. Plain ``http://`` works for local
single-host setups.

The agent runs the same collector set as the server, stamps every record
with the local hostname, and POSTs it to ``POST /api/ingest``. The server
validates the ``X-Agent-Key`` header, attributes the records to the agent,
and runs the full detection pipeline centrally.

On non-Windows hosts (where the Windows collectors cannot import) the agent
falls back to the minimal Linux collectors in ``scripts/linux_collect.py``
(auth.log logon events, network connections, new processes).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)-7s | %(message)s"
)
logger = logging.getLogger("baraq.agent")

AGENT_CONFIG_DIR = Path(
    os.environ.get(
        "BARAQ_AGENT_CONFIG_DIR",
        str(Path.home() / "AppData" / "Local" / "BARAQAgent"),
    )
)
AGENT_CONFIG_FILE = AGENT_CONFIG_DIR / "agent.config.json"
AGENT_TASK_NAME = "BARAQ Agent"
#: Fleet auto-update (roadmap 3.4): reported on every ingest so the fleet
#: view can spot stale agents; update_agent commands target this version.
AGENT_VERSION = "2.0.0"


def _os_banner() -> str:
    """Short OS banner for the fleet view (e.g. 'Windows 10.0.19045')."""
    try:
        import platform

        if sys.platform.startswith("win"):
            return platform.platform(terse=True)
        return platform.platform()
    except Exception:
        return sys.platform


def make_tls_context(
    tls_ca: str | None = None, no_verify: bool = False
) -> ssl.SSLContext | None:
    """Build the SSL context used for https:// server URLs.

    * ``tls_ca`` - PEM file to pin (the central server's self-signed cert);
      verification then succeeds without touching the system store.
    * ``no_verify`` - lab-only: accept any certificate (logs a warning).
    * neither - the default system store is used (imported CAs only).
    Returns ``None`` for plain http:// URLs (no TLS involved).
    """
    if no_verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        logger.warning(
            "TLS verification disabled (--no-verify) - use only in isolated labs"
        )
        return ctx
    if tls_ca:
        ctx = ssl.create_default_context(cafile=tls_ca)
        logger.info("Pinning central TLS certificate: %s", tls_ca)
        return ctx
    return None


def _request(
    base: str,
    path: str,
    key: str,
    payload: dict | None = None,
    method: str = "GET",
    tls_ca: str | None = None,
    no_verify: bool = False,
) -> dict:
    url = base.rstrip("/") + path
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "X-Agent-Key": key},
        method=method,
    )
    context = make_tls_context(tls_ca, no_verify)
    with urllib.request.urlopen(req, timeout=30, context=context) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _run(cmd: list[str]) -> tuple[str, int]:
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return (proc.stdout + proc.stderr).strip(), proc.returncode


def execute_command(cmd: dict) -> dict:
    """Execute one remote command locally; returns the result report dict."""
    action, target = cmd.get("action", ""), cmd.get("target", "")
    if action == "block_ip":
        out, code = _run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name=BARAQ Block {target}",
                "dir=in",
                "action=block",
                f"remoteip={target}",
                "enable=yes",
            ]
        )
        if code != 0:
            out, code = _run(
                [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=BARAQ Block {target}",
                    "dir=out",
                    "action=block",
                    f"remoteip={target}",
                    "enable=yes",
                ]
            )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "kill_process":
        out, code = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-Process -Name {target} -ErrorAction SilentlyContinue | Stop-Process -Force",
            ]
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "quarantine":
        q = os.path.join(os.environ.get("SystemDrive", "C:"), "BARAQ-Quarantine")
        out, code = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    f"if (-not (Test-Path '{q}')) {{ New-Item -ItemType Directory -Path '{q}' | Out-Null }}; "
                    f"Move-Item -LiteralPath '{target}' -Destination '{q}' -Force"
                ),
            ]
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "isolate":
        out, code = _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        if code == 0:
            out, code = _run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        f"New-NetFirewallRule -DisplayName 'BARAQ Isolate {target}' -Direction Inbound -Action Block -Profile Any | Out-Null; "
                        f"New-NetFirewallRule -DisplayName 'BARAQ Isolate {target} Out' -Direction Outbound -Action Block -Profile Any | Out-Null"
                    ),
                ]
            )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "disable_account":
        out, code = _run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Disable-LocalUser -Name '{target}' -ErrorAction Stop",
            ]
        )
        return {"status": "success" if code == 0 else "failed", "detail": out or "ok"}
    if action == "escalate":
        logger.warning(
            "Operator escalated agent %s - manual review required", cmd.get("agent_id")
        )
        return {"status": "success", "detail": "Acknowledged by operator"}
    if action == "update_agent":
        # Roadmap 3.4 auto-update: try the configured updater, else record the
        # rollout. The updater (scripts/agent_updater.ps1) swaps the agent files
        # and restarts the scheduled task; absence of a real updater is a
        # no-op that still acknowledges the rollout.
        updater = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "agent_updater.ps1"
        )
        if os.path.exists(updater):
            out, code = _run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    updater,
                    "-Version",
                    target,
                ]
            )
            return {
                "status": "success" if code == 0 else "failed",
                "detail": out or f"updated to {target}",
            }
        return {
            "status": "success",
            "detail": f"target version {target} recorded (no updater configured)",
        }
    return {"status": "failed", "detail": f"Unknown action: {action}"}


def collect() -> list[dict]:
    """Collect telemetry: Windows collector stack, else the Linux fallback."""
    from backend.collectors import CollectorManager

    host = socket.gethostname()
    records = []
    for record in CollectorManager().collect():
        record["host"] = host
        records.append(record)
    return records


def collect_fallback() -> list[dict]:
    """Non-Windows hosts: use the minimal Linux collectors."""
    host = socket.gethostname()
    records = []
    try:
        from scripts.linux_collect import collect as linux_collect

        for record in linux_collect():
            record["host"] = host
            records.append(record)
    except ImportError as exc:
        logger.warning("No collectors available on this platform: %s", exc)
    return records


def load_config(path: Path | None = None) -> dict:
    """Merge agent.config.json with the environment; CLI flags win later."""
    path = path or AGENT_CONFIG_FILE
    cfg: dict = {}
    try:
        cfg = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        pass
    except ValueError as exc:
        logger.warning("Ignoring malformed agent config %s: %s", path, exc)
    for key in ("interval",):
        try:
            cfg[key] = int(cfg[key])
        except (KeyError, TypeError, ValueError):
            cfg.setdefault(key, 15)
    return cfg


def save_config(values: dict, path: Path | None = None) -> Path:
    path = path or AGENT_CONFIG_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, indent=2), encoding="utf-8")
    return path


def _agent_launcher_python() -> tuple[str, list[str]]:
    """Return (launcher target, args) that survive reboots for the current install."""
    if getattr(sys, "frozen", False):
        return sys.executable, ["--config", str(AGENT_CONFIG_FILE)]
    return sys.executable, [
        "-u",
        str(Path(__file__).resolve()),
        "--config",
        str(AGENT_CONFIG_FILE),
    ]


def install_task(values: dict) -> None:
    """Register the agent as a logon scheduled task (no admin rights needed)."""
    launcher = AGENT_CONFIG_DIR / "agent_launcher.ps1"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    target, args = _agent_launcher_python()
    quoted = "', '".join(arg.replace("'", "''") for arg in args)
    launcher.write_text(
        "$ErrorActionPreference = 'Stop'\n"
        f"Start-Process -FilePath '{target}' -ArgumentList @('{quoted}') -WindowStyle Hidden\n",
        encoding="utf-8",
    )
    quote = subprocess.list2cmdline
    cmd = (
        "schtasks",
        "/Create",
        "/F",
        "/TN",
        AGENT_TASK_NAME,
        "/TR",
        quote(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-WindowStyle",
                "Hidden",
                "-File",
                str(launcher),
            ],
        ),
        "/SC",
        "ONLOGON",
        "/RL",
        "LIMITED",
    )
    out, code = _run(list(cmd))
    if code != 0:
        raise RuntimeError(f"Could not register scheduled task: {out}")
    _run(["schtasks", "/Run", "/TN", AGENT_TASK_NAME])
    logger.info(
        "Agent installed: %s -> %s (task '%s', starts at every logon)",
        target,
        values.get("server"),
        AGENT_TASK_NAME,
    )


def uninstall_task(purge: bool) -> None:
    out, code = _run(["schtasks", "/Delete", "/F", "/TN", AGENT_TASK_NAME])
    if code == 0:
        logger.info("Scheduled task '%s' removed", AGENT_TASK_NAME)
    else:
        logger.info("No task to remove (%s)", out.strip() or "not registered")
    if purge:
        import shutil

        shutil.rmtree(AGENT_CONFIG_DIR, ignore_errors=True)
        AGENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("Config directory purged: %s", AGENT_CONFIG_DIR)


def configure_logging(log_file: str | None) -> None:
    """Send INFO+ output to a file too (invisible when launched windowed)."""
    if not log_file:
        return
    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)-7s | %(name)s | %(message)s")
    )
    logger.addHandler(handler)


def main() -> None:
    os.environ.setdefault("BARAQ_SKIP_SECRET_GEN", "1")
    os.environ.setdefault(
        "BARAQ_DATABASE_URL",
        "postgresql+psycopg://postgres@127.0.0.1:55432/baraq",
    )
    parser = argparse.ArgumentParser(description="BARAQ remote telemetry agent")
    parser.add_argument(
        "--server", default=None, help="Central BARAQ API (HTTPS standard, port 8443)"
    )
    parser.add_argument("--key", default=None, help="Agent key (X-Agent-Key)")
    parser.add_argument(
        "--interval", type=int, default=None, help="Collection interval (seconds)"
    )
    parser.add_argument(
        "--tls-ca",
        default=None,
        help="PEM cert file of the central server (certs/baraq.crt) to pin",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="LAB ONLY: skip TLS certificate verification",
    )
    parser.add_argument(
        "--config",
        default=str(AGENT_CONFIG_FILE),
        help="JSON config file (server/key/interval/tls-ca)",
    )
    parser.add_argument(
        "--log",
        default=str(AGENT_CONFIG_DIR / "agent.log"),
        help="Append log output to this file",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Register as an autostart task and start agent now",
    )
    parser.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove the autostart task (--purge deletes the config)",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="With --uninstall: also delete the config directory",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log debug-level detail (collector failures, batches)",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    configure_logging(args.log if args.log else None)

    if args.uninstall:
        uninstall_task(args.purge)
        return

    cfg = load_config(Path(args.config))
    server = args.server or cfg.get("server") or "https://127.0.0.1:8443"
    key = args.key or cfg.get("key") or "baraq-agent-dev"
    interval = args.interval or cfg.get("interval") or 15
    tls_ca = args.tls_ca or cfg.get("tls_ca")
    no_verify = args.no_verify or bool(cfg.get("no_verify"))

    if args.install:
        values = {
            "server": server,
            "key": key,
            "interval": interval,
            "tls_ca": tls_ca or "",
            "no_verify": no_verify,
            "log": args.log,
        }
        save_config(values, Path(args.config))
        install_task(values)
        return

    host = socket.gethostname()
    logger.info("BARAQ agent starting (host=%s, server=%s)", host, server)
    while True:
        try:
            try:
                pending = _request(
                    server,
                    "/api/commands/pending",
                    key,
                    tls_ca=tls_ca,
                    no_verify=no_verify,
                )
                for cmd in pending.get("items", []):
                    report = execute_command(cmd)
                    try:
                        _request(
                            server,
                            f"/api/commands/{cmd['id']}/result",
                            key,
                            report,
                            method="POST",
                            tls_ca=tls_ca,
                            no_verify=no_verify,
                        )
                        logger.info(
                            "Command #%s (%s %s) -> %s",
                            cmd["id"],
                            cmd["action"],
                            cmd["target"],
                            report["status"],
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to report command #%s: %s", cmd.get("id"), exc
                        )
            except Exception as exc:
                logger.warning("Command poll failed: %s", exc)

            records = []
            try:
                records = collect()
            except Exception as exc:
                logger.debug("Windows collectors unavailable (%s); Linux fallback", exc)
                records = collect_fallback()
            if records:
                result = _request(
                    server,
                    "/api/ingest",
                    key,
                    {
                        "records": records,
                        "host": host,
                        "agent_version": AGENT_VERSION,
                        "os_info": _os_banner(),
                    },
                    method="POST",
                    tls_ca=tls_ca,
                    no_verify=no_verify,
                )
                logger.info(
                    "Shipped %d records -> %s alerts",
                    result.get("collected", 0),
                    result.get("alerts_created", 0),
                )
            else:
                logger.debug("No records collected")
        except Exception as exc:
            logger.warning("Agent cycle failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
