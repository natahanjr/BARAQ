"""Per-university fleet provisioning for a multi-tenant SentinelSOC console.

Batch-registers the agent hosts of one campus at a time against the central
server, tagging every host with the university's org id so its telemetry,
alerts and dashboards are isolated from other tenants (see
``SENTINEL_AGENT_ORGS`` / ``agent_org`` in backend/config.py).

    venv\\Scripts\\python scripts\\provision_university.py setup univ-a https://soc.example.com:8443 ^
        --org-name "University A" --hosts ws-lib-01,ws-lib-02,ws-chem-04 ^
        --tls-cert certs\\sentinel.crt

    venv\\Scripts\\python scripts\\provision_university.py list
    venv\\Scripts\\python scripts\\provision_university.py revoke-org univ-a

The manifest written to ``agent_configs/<org>-manifest.json`` contains one
launch command per host (key included once). Distribute each command to its
host over a trusted channel, start it, and the host appears in
**System -> Connected Endpoints** tagged with the org after its first cycle.
Restart the SentinelSOC service after setup so the new keys load.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import APP_DIR  # noqa: E402
from backend.vault import SecretVault, get_vault_path  # noqa: E402
from scripts import provision_agent as prov  # noqa: E402

MANIFEST_DIR = APP_DIR / "agent_configs"


def _resolve_tls_cert(server: str, tls_cert: str) -> str:
    if tls_cert:
        return tls_cert
    return "certs\\sentinel.crt" if server.startswith("https://") else ""


def _agent_cmd(server: str, key: str, interval: int, tls_cert: str) -> str:
    ca = f" --tls-ca {tls_cert}" if tls_cert else ""
    return f'python scripts/agent.py --server {server} --key "{key}" --interval {interval}{ca}'


def provision_org(vault: SecretVault, org: str, server: str, hosts: list[str],
                  org_name: str = "", tls_cert: str = "", interval: int = 15) -> Path:
    """Register every host of one university; returns the manifest path."""
    tls_cert = _resolve_tls_cert(server, tls_cert)
    MANIFEST_DIR.mkdir(exist_ok=True)
    manifest = {
        "org": org,
        "org_name": org_name or org,
        "server": server,
        "tls_ca": tls_cert or None,
        "interval": interval,
        "hosts": {},
    }
    for agent_id in hosts:
        key, cfg = prov.provision_host(vault, agent_id, server, org=org,
                                       tls_cert=tls_cert, interval=interval)
        manifest["hosts"][agent_id] = {
            "key": key,
            "config": cfg.name,
            "command": _agent_cmd(server, key, interval, tls_cert),
        }
    path = MANIFEST_DIR / f"{org}-manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def list_orgs(vault: SecretVault) -> dict[str, list[str]]:
    orgmap = prov.load_org_map(vault)
    grouped: dict[str, list[str]] = {}
    for agent_id, org in sorted(orgmap.items()):
        grouped.setdefault(org, []).append(agent_id)
    return grouped


def revoke_org(vault: SecretVault, org: str) -> int:
    """Revoke every host of one org and drop its manifest."""
    orgmap = prov.load_org_map(vault)
    members = [a for a, o in orgmap.items() if o == org]
    if not members:
        print(f"org '{org}' has no provisioned agents")
        return 1
    keymap = prov.load_key_map(vault)
    for agent_id in members:
        key = next(k for k, v in keymap.items() if v == agent_id)
        keymap.pop(key, None)
        orgmap.pop(agent_id, None)
        prov.drop_agent_config(agent_id)
    prov.save_key_map(vault, keymap)
    prov.save_org_map(vault, orgmap)
    (MANIFEST_DIR / f"{org}-manifest.json").unlink(missing_ok=True)
    print(f"revoked org '{org}': {len(members)} host(s)")
    return 0


def _vault() -> SecretVault:
    return SecretVault(get_vault_path())


def cmd_setup(args: argparse.Namespace) -> int:
    hosts = [h for h in (h.strip() for h in args.hosts.split(",")) if h]
    manifest = provision_org(_vault(), args.org, args.server, hosts,
                             args.org_name, args.tls_cert, args.interval)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    print(f"university '{args.org}' -> {len(hosts)} host(s) provisioned")
    print(f"  org display : {data['org_name']}")
    print(f"  server      : {data['server']}")
    print(f"  tls pin     : {data['tls_ca'] or '(none - plain http)'}")
    print(f"  manifest    : {manifest}")
    print("\nDistribute one launch command per host (keys shown once):")
    for agent_id, info in data["hosts"].items():
        print(f"\n  [{agent_id}]")
        print(f"  {info['command']}")
    print("\nRestart the SentinelSOC service to load the new keys.")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    grouped = list_orgs(_vault())
    if not grouped:
        print("(no orgs provisioned)")
        return 0
    for org, hosts in grouped.items():
        print(f"{org:<16} {', '.join(hosts)}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    return revoke_org(_vault(), args.org)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    setup = sub.add_parser("setup", help="provision all hosts of one university")
    setup.add_argument("org", help="stable org id, e.g. univ-a")
    setup.add_argument("server",
                       help="central server URL, e.g. https://soc.example.com:8443")
    setup.add_argument("--org-name", default="", help="display name of the university")
    setup.add_argument("--hosts", required=True,
                       help="comma-separated agent ids of the campus hosts")
    setup.add_argument("--tls-cert", default="",
                       help="PEM cert of the central server "
                            "(defaults to certs\\sentinel.crt for https servers)")
    setup.add_argument("--interval", type=int, default=15)
    setup.set_defaults(func=cmd_setup)
    sub.add_parser("list", help="list orgs and their hosts").set_defaults(func=cmd_list)
    revoke = sub.add_parser("revoke-org", help="revoke every host of one org")
    revoke.add_argument("org")
    revoke.set_defaults(func=cmd_revoke)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())