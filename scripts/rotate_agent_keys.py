"""Rotate or bulk-generate BARAQ agent keys.

    venv\\Scripts\\python scripts\\rotate_agent_keys.py list
    venv\\Scripts\\python scripts\\rotate_agent_keys.py rotate ws-it-01
    venv\\Scripts\\python scripts\\rotate_agent_keys.py rotate-all
    venv\\Scripts\\python scripts\\rotate_agent_keys.py generate --count 1000 --output agent_configs\\load_test_keys.json

Keys live in the DPAPI vault under BARAQ_AGENT_KEYS (never in git).
``generate`` writes a one-shot JSON map for load tests / fixtures only -
keep that file outside the repo.

After any rotate/rotate-all, restart the BARAQ service so the new keys load.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.config import APP_DIR
from backend.vault import SecretVault, get_vault_path
from scripts import provision_agent as prov


def _vault() -> SecretVault:
    return SecretVault(get_vault_path())


def cmd_list(_: argparse.Namespace) -> int:
    vault = _vault()
    keymap = prov.load_key_map(vault)
    orgmap = prov.load_org_map(vault)
    if not keymap:
        print("(no agent keys in vault)")
        return 0
    print(f"{'agent-id':<24} {'org':<12} {'key (prefix)':<32}")
    for key, agent_id in sorted(keymap.items(), key=lambda kv: kv[1]):
        org = orgmap.get(agent_id, "")
        print(f"{agent_id:<24} {org:<12} {key[:30]}...")
    return 0


def _rotate_one(vault: SecretVault, agent_id: str, server: str, tls_cert: str, interval: int) -> str | None:
    keymap = prov.load_key_map(vault)
    if agent_id not in keymap.values():
        print(f"agent-id '{agent_id}' not found")
        return None
    old_key = next(k for k, v in keymap.items() if v == agent_id)
    orgmap = prov.load_org_map(vault)
    org = orgmap.get(agent_id, "")
    # Drop old key + config, then re-provision with a fresh key.
    keymap.pop(old_key, None)
    prov.save_key_map(vault, keymap)
    orgmap.pop(agent_id, None)
    if org:
        orgmap[agent_id] = org
        prov.save_org_map(vault, orgmap)
    prov.drop_agent_config(agent_id)
    new_key, cfg = prov.provision_host(
        vault, agent_id, server, org=org, tls_cert=tls_cert, interval=interval
    )
    print(f"rotated '{agent_id}' -> {new_key[:16]}... (config {cfg.name})")
    return new_key


def cmd_rotate(args: argparse.Namespace) -> int:
    vault = _vault()
    key = _rotate_one(vault, args.agent_id, args.server, args.tls_cert, args.interval)
    if key is None:
        return 1
    print("\nUpdate the endpoint config with the new key, then restart BARAQ.")
    return 0


def cmd_rotate_all(args: argparse.Namespace) -> int:
    vault = _vault()
    keymap = prov.load_key_map(vault)
    if not keymap:
        print("(no agent keys in vault)")
        return 1
    agents = sorted(set(keymap.values()))
    n = 0
    for agent_id in agents:
        if _rotate_one(vault, agent_id, args.server, args.tls_cert, args.interval):
            n += 1
    print(f"\nrotated {n}/{len(agents)} agent key(s).")
    print("Re-distribute configs (or re-run install_agent.ps1) and restart BARAQ.")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    count = max(1, args.count)
    keymap = {f"baraq-lt-{secrets.token_hex(8)}": f"lt-{i:04d}" for i in range(count)}
    payload = json.dumps(keymap, indent=2) + "\n"
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print(f"wrote {count} keys -> {out}")
        print("WARNING: load-test keys only - never import into BARAQ_AGENT_KEYS in production.")
    else:
        sys.stdout.write(payload)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list provisioned agent keys (prefix only)").set_defaults(func=cmd_list)

    rot = sub.add_parser("rotate", help="rotate one agent key")
    rot.add_argument("agent_id")
    rot.add_argument("--server", default="https://127.0.0.1:8443")
    rot.add_argument("--tls-cert", default="")
    rot.add_argument("--interval", type=int, default=15)
    rot.set_defaults(func=cmd_rotate)

    ra = sub.add_parser("rotate-all", help="rotate every agent key in the vault")
    ra.add_argument("--server", default="https://127.0.0.1:8443")
    ra.add_argument("--tls-cert", default="")
    ra.add_argument("--interval", type=int, default=15)
    ra.set_defaults(func=cmd_rotate_all)

    gen = sub.add_parser("generate", help="bulk-generate load-test keys (not vault)")
    gen.add_argument("--count", type=int, default=1000)
    gen.add_argument("--output", default="")
    gen.set_defaults(func=cmd_generate)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
