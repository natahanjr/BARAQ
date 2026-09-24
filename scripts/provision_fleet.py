"""Batch-provision a company fleet of BARAQ agents.

Reads a fleet JSON describing orgs and hosts, registers every host in the
DPAPI vault, and writes a manifest with one install command per endpoint.

    venv\\Scripts\\python scripts\\provision_fleet.py ^
        --fleet agent_configs\\company-fleet.json ^
        --server https://192.168.1.7:8443 ^
        --tls-cert certs\\baraq.crt

Fleet JSON shape:

    {
      "server": "https://192.168.1.7:8443",
      "orgs": {
        "it":     { "name": "IT",     "hosts": ["srv-it-01", "ws-it-01"] },
        "finance":{ "name": "Finance","hosts": ["ws-fin-01", "ws-fin-02"] }
      }
    }

Host entries may be a single name or a range string expanded with
``expand_range``:  ``"ws-01..ws-50"``  ->  ws-01 .. ws-50.

After provisioning, restart the BARAQ service so the new keys load.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import APP_DIR
from backend.vault import SecretVault, get_vault_path
from scripts import provision_agent as prov

MANIFEST_DIR = APP_DIR / "agent_configs"

_RANGE_RE = re.compile(r"^(?P<prefix>.*?)(?P<start>\d+)\.\.(?P<prefix2>.*?)(?P<end>\d+)$")


def expand_range(entry: str) -> list[str]:
    """Expand ``prefix01..prefix50`` or bare ``01..50`` into host names."""
    entry = entry.strip()
    m = _RANGE_RE.match(entry)
    if not m:
        return [entry]
    p1, s = m.group("prefix"), int(m.group("start"))
    p2, e = m.group("prefix2"), int(m.group("end"))
    if p1 != p2 and p2:
        # e.g. "ws-a-01..ws-b-05" — treat as two different prefixes; fall through
        return [entry]
    width = max(len(m.group("start")), len(m.group("end")))
    return [f"{p1}{i:0{width}d}" for i in range(s, e + 1)]


def resolve_tls(server: str, tls_cert: str) -> str:
    if tls_cert:
        return tls_cert
    return "certs\\baraq.crt" if server.startswith("https://") else ""


def install_command(server: str, key: str, org: str, interval: int, tls_cert: str) -> str:
    """PowerShell one-liner for install_agent.ps1 (endpoint side)."""
    ca = f" -TlsCert {tls_cert}" if tls_cert else ""
    # install_agent.ps1 takes -Server -Key -Org -Interval; cert pin is via config
    return (
        f'powershell -ExecutionPolicy Bypass -File scripts\\install_agent.ps1 '
        f'-Server {server} -Key "{key}" -Org {org} -Interval {interval}'
    )


def load_fleet(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if "orgs" not in data:
        raise SystemExit(f"{path}: missing top-level 'orgs' object")
    return data


def provision_fleet(
    fleet: dict,
    server: str,
    tls_cert: str,
    interval: int,
    dry_run: bool = False,
) -> dict:
    tls_cert = resolve_tls(server, tls_cert)
    vault = SecretVault(get_vault_path())
    manifest: dict = {
        "server": server,
        "tls_ca": tls_cert or None,
        "interval": interval,
        "orgs": {},
    }
    total = 0
    skipped = 0

    for org_id, info in fleet["orgs"].items():
        name = info.get("name", org_id)
        raw_hosts = info.get("hosts", [])
        hosts: list[str] = []
        for h in raw_hosts:
            hosts.extend(expand_range(str(h)))
        org_entry = {"name": name, "hosts": {}}
        for agent_id in hosts:
            existing = prov.load_key_map(vault)
            if agent_id in existing.values():
                skipped += 1
                print(f"  skip  {agent_id} (already provisioned)")
                continue
            if dry_run:
                print(f"  would provision {agent_id} [org={org_id}]")
                org_entry["hosts"][agent_id] = {
                    "key": "(dry-run)",
                    "command": install_command(server, "(dry-run)", org_id, interval, tls_cert),
                }
                total += 1
                continue
            key, cfg = prov.provision_host(
                vault, agent_id, server, org=org_id, tls_cert=tls_cert, interval=interval
            )
            org_entry["hosts"][agent_id] = {
                "key": key,
                "config": cfg.name,
                "command": install_command(server, key, org_id, interval, tls_cert),
            }
            total += 1
            print(f"  ok    {agent_id} [org={org_id}]")
        manifest["orgs"][org_id] = org_entry

    manifest["summary"] = {"provisioned": total, "skipped_existing": skipped}
    return manifest


def save_manifest(manifest: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"\nManifest: {path}")


def print_summary(manifest: dict) -> None:
    s = manifest.get("summary", {})
    print("\n" + "=" * 60)
    print(f"  Server     : {manifest['server']}")
    print(f"  TLS pin    : {manifest.get('tls_ca') or '(none)'}")
    print(f"  Provisioned: {s.get('provisioned', 0)}")
    print(f"  Skipped    : {s.get('skipped_existing', 0)} (already in vault)")
    print("=" * 60)
    print("\nInstall commands (run ON each target host):\n")
    for org_id, info in manifest["orgs"].items():
        print(f"  # --- {info['name']} ({org_id}) ---")
        for agent_id, h in info["hosts"].items():
            print(f"  # {agent_id}")
            print(f"  {h['command']}")
        print()
    print("RESTART the BARAQ service so new agent keys are loaded:")
    print("  scripts\\install_service.ps1 fix   # or restart service BARAQ")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fleet", required=True, help="path to fleet JSON")
    p.add_argument("--server", default="", help="override server URL from fleet file")
    p.add_argument("--tls-cert", default="", help="PEM cert path for agent pinning")
    p.add_argument("--interval", type=int, default=15, help="agent push interval seconds")
    p.add_argument("--output", default="", help="manifest output path")
    p.add_argument("--dry-run", action="store_true", help="preview only")
    args = p.parse_args(argv)

    fleet_path = Path(args.fleet)
    if not fleet_path.exists():
        raise SystemExit(f"fleet file not found: {fleet_path}")
    fleet = load_fleet(fleet_path)
    server = args.server or fleet.get("server") or ""
    if not server:
        raise SystemExit("server URL required (--server or fleet JSON 'server')")

    manifest = provision_fleet(fleet, server, args.tls_cert, args.interval, args.dry_run)

    out = Path(args.output) if args.output else MANIFEST_DIR / "company-fleet-manifest.json"
    if not args.dry_run:
        save_manifest(manifest, out)
    print_summary(manifest)
    if args.dry_run:
        print("\n[DRY RUN] nothing written to vault.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
