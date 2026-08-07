"""Real attack campaign runner with recorded ground truth.

Executes a set of *safe, contained* attack simulations against the local host
while the Sentinel collector runs, and records what was actually launched into
``database/campaigns/campaign_<run-id>.json`` so real-telemetry validation can
score detections honestly against real ground truth (no synthetic rows).

Every simulation is local-only (localhost targets, benign payloads, immediate
cleanup) and user-approved. Run with::

    python -m tools.realtime.campaign --run-id campaign_20260806_a --steps all
    python -m tools.realtime.campaign --run-id campaign_20260806_a --steps process-encoded
"""
from __future__ import annotations

import argparse
import base64
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAMPAIGNS_DIR = PROJECT_ROOT / "database" / "campaigns"


class SimulationError(RuntimeError):
    pass


class _Sim:
    """Ground truth for one launched simulation."""

    def __init__(self, sim_id: str, behavior: str, process_name: str, marker: str,
                 targets: list[str] | None = None):
        self.sim_id = sim_id
        self.behavior = behavior
        self.process_name = process_name
        self.marker = marker
        self.targets = targets or []
        self.started_at = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.rc: int | None = None

    def finish(self, rc: int | None) -> None:
        self.finished_at = datetime.now(timezone.utc)
        self.rc = rc

    def to_dict(self) -> dict:
        return {
            "sim_id": self.sim_id,
            "behavior": self.behavior,
            "process_name": self.process_name,
            "marker": self.marker,
            "targets": self.targets,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "returncode": self.rc,
        }


def _marker_payload(marker: str) -> str:
    return (
        "$m = '" + marker + "'; "
        "Write-Output ('campaign-marker ' + $m); "
        "Start-Sleep -Milliseconds 300"
    )


def _run_sim(args: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return proc.returncode, (proc.stdout or "")[:200]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)


def sim_process_encoded(marker: str) -> tuple[list[str], str]:
    """Powershell -EncodedCommand launcher (attacker-style obfuscation)."""
    payload = _marker_payload(marker)
    encoded = base64.b64encode(payload.encode("utf-16-le")).decode("ascii")
    return ["powershell", "-NoProfile", "-EncodedCommand", encoded], "powershell.exe"


def sim_process_masquerade(marker: str) -> tuple[list[str], str]:
    """Copy of cmd.exe masquerading as svchost.exe from %TEMP%."""
    src = r"C:\Windows\System32\cmd.exe"
    name = f"svchost_{uuid.uuid4().hex[:8]}.exe"
    dst = Path(tempfile.gettempdir()) / name
    if not Path(src).exists():
        raise SimulationError(f"missing source binary {src}")
    shutil.copy2(src, dst)
    args = [str(dst), "/c", f"echo {marker}"]
    return args, name


def sim_login_spray(marker: str) -> tuple[list[str], str]:
    """Failed-login spray via net use against localhost shares (4625s)."""
    script = []
    for i in range(6):
        share = f"\\\\localhost\\IPC$"
        # PS-correct suppression: `>nul` is cmd syntax and makes PS try to open
        # `nul` as a device file (Failing), aborting `net use` BEFORE the logon
        # attempt. `> $null 2>&1` keeps the failure silent but still logs an
        # actual failed network logon (Event 4625).
        script.append(f"net use {share} /user:campaign_user_{marker} wrong-pass-{i} > $null 2>&1")
    script.append(f"echo {marker}")
    ps = ["powershell", "-NoProfile", "-Command", "; ".join(script)]
    return ps, "powershell.exe"


def sim_network_sweep(marker: str) -> tuple[list[str], str]:
    """Localhost-LAN TCP port sweep (1..120) - high connection volume.

    Targets the host's own LAN address instead of 127.0.0.1 so the sweep is
    visible to the network rules (which ignore loopback sources) while still
    being 100% local and contained.
    """
    try:
        target = socket.gethostbyname(socket.gethostname())
    except OSError:
        target = "127.0.0.1"
    ports = list(range(1, 121))
    script = (
        "foreach ($p in @(" + ",".join(str(p) for p in ports) + ")) {"
        f"$c = New-Object System.Net.Sockets.TcpClient; try {{ $t = $c.ConnectAsync('{target}', $p); "
        "$t.Wait(150) } catch {}; $c.Close() }"
    )
    ps = ["powershell", "-NoProfile", "-Command", script + f"; Write-Output '{marker}'"]
    return ps, "powershell.exe"


def sim_process_volume(marker: str) -> tuple[list[str], str]:
    """High-volume local file copies (rapid process churn)."""
    src = Path(tempfile.gettempdir()) / f"campaign_src_{uuid.uuid4().hex[:6]}.txt"
    src.write_text(marker, encoding="utf-8")
    script = "; ".join(
        f"Copy-Item -LiteralPath '{src}' -Destination '{src.parent / f'c_{i}.txt'}' -Force"
        for i in range(40)
    )
    ps = ["powershell", "-NoProfile", "-Command", script]
    return ps, "powershell.exe"


_SIMS = {
    "process-encoded": sim_process_encoded,
    "process-masquerade": sim_process_masquerade,
    "login-spray": sim_login_spray,
    "network-sweep": sim_network_sweep,
    "process-volume": sim_process_volume,
}


def run_campaign(run_id: str, steps: list[str] | None = None, marker: str | None = None) -> dict:
    """Run the selected simulations, recording ground truth to JSON."""
    CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
    marker = marker or uuid.uuid4().hex[:8]
    steps = steps or list(_SIMS)
    unknown = [s for s in steps if s not in _SIMS]
    if unknown:
        raise ValueError(f"unknown steps {unknown}; available: {list(_SIMS)}")

    results: list[dict] = []
    for step in steps:
        sim = _Sim(sim_id=step, behavior=step.split("-")[0], process_name="", marker=marker)
        try:
            args, sim.process_name = _SIMS[step](marker)
            rc, out = _run_sim(args)
            sim.finish(rc)
        except SimulationError as exc:
            sim.finish(None)
            out = str(exc)
        entry = sim.to_dict()
        entry["stdout"] = out
        results.append(entry)
        print(f"[campaign] {step}: rc={sim.rc} {out.strip()[:100]}")

    started = min(r["started_at"] for r in results)
    ended = max(r["finished_at"] or started for r in results)
    manifest = {
        "run_id": run_id,
        "marker": marker,
        "started_at": started,
        "finished_at": ended,
        "window_seconds": 60,
        "ground_truth": results,
    }
    path = CAMPAIGNS_DIR / f"{run_id}.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"[campaign] manifest written to {path}")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default=f"campaign_{datetime.now():%Y%m%d_%H%M%S}")
    parser.add_argument("--steps", nargs="*", default=None)
    parser.add_argument("--marker", default=None)
    args = parser.parse_args()
    sys.exit(0 if run_campaign(args.run_id, args.steps, args.marker) else 1)
