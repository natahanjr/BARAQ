"""Enable/revert Windows logging policies needed for real attack telemetry.

The host must log what the detector models:
* 4688 (Audit Process Creation) so process events appear in the Security channel
* command lines on 4688 (ProcessCreationIncludeCmdLine_Enabled)
* PowerShell script-block logging (4104) so encoded executions are visible

Every change records its prior state in ``database/realtime_policy_state.json``
so :func:`revert` can restore the host exactly. No policy change is made
unless this module is explicitly invoked (``python -m tools.realtime.logging_policy``).
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger("baraq.realtime.policy")

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_FILE = PROJECT_ROOT / "database" / "realtime_policy_state.json"

_AUDIT_SUBCATEGORIES = ["Process Creation", "Logon"]
_CMD_LINE_KEY = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
_CMD_LINE_VALUE = "ProcessCreationIncludeCmdLine_Enabled"
_PS_KEY = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
_PS_VALUE = "EnableScriptBlockLogging"


def _run(args: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def _auditpol_get(subcategory: str) -> str:
    code, out = _run(["auditpol", "/get", f"/subcategory:{subcategory}"])
    return out.strip() if code == 0 else ""


def _auditpol_set(subcategory: str, *settings: str) -> str:
    code, out = _run(["auditpol", "/set", f"/subcategory:{subcategory}", *settings])
    return "ok" if code == 0 else f"failed: {out[:120]}"


def _reg_query(key: str, value: str) -> str | None:
    code, out = _run(["reg", "query", key, "/v", value])
    if code != 0:
        return None
    for line in out.splitlines():
        if "REG_DWORD" in line:
            parts = line.strip().split()
            return parts[-1] if parts else None
    return None


def _reg_set(key: str, value: str, data: str) -> bool:
    code, _ = _run(
        ["reg", "add", key, "/v", value, "/t", "REG_DWORD", "/d", data, "/f"]
    )
    return code == 0


def _reg_delete(key: str, value: str) -> None:
    _run(["reg", "delete", key, "/v", value, "/f"])


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    return {}


def _save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def enable() -> dict:
    """Enable process-creation + logon-failure auditing and PS script-block
    logging; records every prior state so :func:`revert` restores the host."""
    state = _load_state()
    for sub in _AUDIT_SUBCATEGORIES:
        prior = _auditpol_get(sub)
        if prior:
            state.setdefault(f"auditpol_{sub.lower().replace(' ', '_')}", prior)
    prior_cmdline = _reg_query(_CMD_LINE_KEY, _CMD_LINE_VALUE)
    if prior_cmdline:
        state.setdefault("cmdline_dword", prior_cmdline)
    prior_ps = _reg_query(_PS_KEY, _PS_VALUE)
    if prior_ps:
        state.setdefault("psblock_dword", prior_ps)

    results: dict[str, str] = {}
    for sub in _AUDIT_SUBCATEGORIES:
        results[f"audit_{sub.lower().replace(' ', '_')}"] = _auditpol_set(
            sub, "/success:enable", "/failure:enable"
        )
    results["cmdline_reg"] = (
        "ok" if _reg_set(_CMD_LINE_KEY, _CMD_LINE_VALUE, "1") else "failed"
    )
    results["psblock_reg"] = "ok" if _reg_set(_PS_KEY, _PS_VALUE, "1") else "failed"

    state["enabled_at"] = __import__("datetime").datetime.now().isoformat()
    _save_state(state)
    logger.info("Logging policies enabled: %s", results)
    return {"enabled": results, "prior_state": state}


def revert() -> dict:
    """Restore the host to its pre-campaign policy state."""
    state = _load_state()
    results: dict[str, str] = {}
    for sub in _AUDIT_SUBCATEGORIES:
        key = f"auditpol_{sub.lower().replace(' ', '_')}"
        prior = state.get(key)
        if prior:
            # auditpol accepts the raw success/failure set string, e.g.
            # "No Auditing" / "Success and Failure".
            results[key] = _auditpol_set(sub, prior)
        else:
            results[key] = "no prior state"
    prior_cmdline = state.get("cmdline_dword")
    if prior_cmdline:
        results["cmdline_reg"] = (
            "ok"
            if _reg_set(_CMD_LINE_KEY, _CMD_LINE_VALUE, prior_cmdline)
            else "failed"
        )
    else:
        _reg_delete(_CMD_LINE_KEY, _CMD_LINE_VALUE)
        results["cmdline_reg"] = "reverted (removed)"
    prior_ps = state.get("psblock_dword")
    if prior_ps:
        results["psblock_reg"] = (
            "ok" if _reg_set(_PS_KEY, _PS_VALUE, prior_ps) else "failed"
        )
    else:
        _reg_delete(_PS_KEY, _PS_VALUE)
        results["psblock_reg"] = "reverted (removed)"
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    logger.info("Logging policies reverted: %s", results)
    return {"reverted": results}


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    action = sys.argv[1] if len(sys.argv) > 1 else "enable"
    if action == "revert":
        print(revert())
    else:
        print(enable())
