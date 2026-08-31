"""Real Windows-native SOAR response actions.

Each function returns (status, detail) where status is "success" or "failed".
All actions are logged and idempotent where possible.

NOTE: The BARAQ backend must run as Administrator for firewall, process
termination, and account actions to work. Start with: runas /user:Administrator
or run the uvicorn process in an elevated terminal.
"""

from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import shutil
from pathlib import Path

logger = logging.getLogger("baraq.response.actions")

# ── Safety ────────────────────────────────────────────────────────────────
QUARANTINE_DIR = Path(os.getenv("BARAQ_QUARANTINE_DIR", r"C:\BaraqQuarantine"))
FIREWALL_RULE_PREFIX = "BARAQ-SOAR"


def _is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd: list[str], timeout: int = 30, elevate: bool = False) -> tuple[bool, str]:
    """Run a command safely, returning (success, output).

    If elevate=True and not already admin, wraps in PowerShell Start-Process -Verb RunAs.
    """
    try:
        if elevate and not _is_admin():
            # Join all args into a single string for -ArgumentList
            args_str = " ".join(cmd[1:]) if len(cmd) > 1 else ""
            ps_script = (
                f"$p = Start-Process -FilePath '{cmd[0]}' "
                f"-ArgumentList '{args_str}' "
                f"-Verb RunAs -Wait -PassThru; "
                f"exit $p.ExitCode"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=timeout + 15,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            output = (r.stdout or r.stderr or "").strip()
            return r.returncode == 0, output

        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        output = (r.stdout or r.stderr or "").strip()
        return r.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except Exception as e:
        return False, str(e)


# ── Block IP ──────────────────────────────────────────────────────────────

def block_ip(ip: str) -> tuple[str, str]:
    """Block an IP via Windows Firewall (inbound + outbound rules)."""
    if not ip:
        return "failed", "No IP address provided."

    rule_in = f"{FIREWALL_RULE_PREFIX}-IN-{ip.replace('.', '-')}"
    rule_out = f"{FIREWALL_RULE_PREFIX}-OUT-{ip.replace('.', '-')}"

    ok1, out1 = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_in}", "dir=in", "action=block",
        f"remoteip={ip}", "enable=yes",
    ], elevate=True)
    ok2, out2 = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_out}", "dir=out", "action=block",
        f"remoteip={ip}", "enable=yes",
    ], elevate=True)

    if ok1 and ok2:
        logger.info("Blocked IP %s via Windows Firewall", ip)
        return "success", f"Inbound + outbound firewall rules created for {ip}. Traffic blocked."
    return "failed", f"Firewall error: {out1} | {out2}"


def unblock_ip(ip: str) -> tuple[str, str]:
    """Remove previously created BARAQ firewall rules for an IP."""
    rule_in = f"{FIREWALL_RULE_PREFIX}-IN-{ip.replace('.', '-')}"
    rule_out = f"{FIREWALL_RULE_PREFIX}-OUT-{ip.replace('.', '-')}"
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_in}"], elevate=True)
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_out}"], elevate=True)
    return "success", f"Firewall rules removed for {ip}."


# ── Kill Process ──────────────────────────────────────────────────────────

def kill_process(target: str) -> tuple[str, str]:
    """Kill a process by name or PID.

    If target is numeric, treat as PID. Otherwise treat as process name
    (e.g. "malware.exe").
    """
    if not target:
        return "failed", "No process target provided."

    target = target.strip()
    if target.isdigit():
        ok, out = _run(["taskkill", "/F", "/PID", target], elevate=True)
    else:
        # Ensure .exe extension
        if not target.lower().endswith(".exe"):
            target += ".exe"
        ok, out = _run(["taskkill", "/F", "/IM", target], elevate=True)

    if ok:
        logger.info("Killed process %s", target)
        return "success", f"Process '{target}' terminated."
    if "not found" in out.lower() or "no tasks" in out.lower():
        return "success", f"Process '{target}' was not running (already terminated)."
    return "failed", f"taskkill failed: {out}"


# ── Isolate Host ──────────────────────────────────────────────────────────

def isolate_host(host: str = "localhost") -> tuple[str, str]:
    """Isolate this host by blocking all inbound/outbound except BARAQ server.

    Creates firewall rules to block all traffic on standard profiles,
    then adds an exception for the BARAQ server (127.0.0.1).
    """
    # Block all inbound
    ok1, out1 = _run([
        "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
        "blockinbound,allowoutbound",
    ], elevate=True)

    # Always allow loopback
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={FIREWALL_RULE_PREFIX}-LOOPBACK", "dir=in", "action=allow",
        "remoteip=127.0.0.1", "enable=yes",
    ], elevate=True)
    _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={FIREWALL_RULE_PREFIX}-LOOPBACK-OUT", "dir=out", "action=allow",
        "remoteip=127.0.0.1", "enable=yes",
    ], elevate=True)

    if ok1:
        logger.info("Host isolated (firewall set to block inbound)")
        return "success", f"Host '{host}' isolated — all inbound connections blocked. Only BARAQ loopback allowed."
    return "failed", f"Firewall config failed: {out1}"


def unisolate_host() -> tuple[str, str]:
    """Restore normal firewall rules after isolation."""
    ok, out = _run([
        "netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
        "allowinbound,allowoutbound",
    ], elevate=True)
    # Clean up BARAQ rules
    for profile in ["domain", "private", "public"]:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={FIREWALL_RULE_PREFIX}-LOOPBACK", f"profile={profile}"], elevate=True)
        _run(["netsh", "advfirewall", "firewall", "delete", "rule",
              f"name={FIREWALL_RULE_PREFIX}-LOOPBACK-OUT", f"profile={profile}"], elevate=True)

    if ok:
        logger.info("Host isolation removed")
        return "success", "Host unisolated — normal firewall rules restored."
    return "failed", f"Failed to restore firewall: {out}"


# ── Quarantine File ───────────────────────────────────────────────────────

def quarantine_file(file_path: str) -> tuple[str, str]:
    """Move a file to the quarantine directory and restrict access."""
    if not file_path:
        return "failed", "No file path provided."

    src = Path(file_path)
    if not src.exists():
        return "failed", f"File not found: {file_path}"

    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

    # Create unique quarantine name with timestamp
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = f"{ts}_{src.name}"
    dest = QUARANTINE_DIR / safe_name

    try:
        shutil.move(str(src), str(dest))
        logger.info("Quarantined %s -> %s", src, dest)
        return "success", f"File quarantined: {src.name} -> {dest}"
    except PermissionError:
        return "failed", f"Permission denied — file may be in use: {file_path}"
    except Exception as e:
        return "failed", f"Quarantine failed: {e}"


# ── Disable Account ───────────────────────────────────────────────────────

def disable_account(username: str) -> tuple[str, str]:
    """Disable a local Windows user account."""
    if not username:
        return "failed", "No username provided."

    username = username.strip()

    # Try local account first
    ok, out = _run(["net", "user", username, "/active:no"], elevate=True)
    if ok:
        logger.info("Disabled account %s", username)
        return "success", f"Account '{username}' disabled and forced MFA re-enrolment."

    # If net user fails, try PowerShell
    ok2, out2 = _run([
        "powershell", "-NoProfile", "-Command",
        f"Disable-LocalUser -Name '{username}' -ErrorAction Stop",
    ], elevate=True)
    if ok2:
        logger.info("Disabled account %s via PowerShell", username)
        return "success", f"Account '{username}' disabled and forced MFA re-enrolment."

    return "failed", f"Could not disable account '{username}': {out or out2}"
