"""Provision, list, and revoke SentinelSOC agent credentials.

Agents authenticate to ``POST /api/ingest`` (and the command channel) with a
per-``X-Agent-Key`` header. Keys live inside the app's DPAPI vault under
``SENTINEL_AGENT_KEYS`` (JSON map {"key": "agent-id"}). This script is the
single supported way to add or remove a fleet member - never hand-edit the
vault and never paste keys into chats/CI logs.

    venv\\Scripts\\python scripts\\provision_agent.py add edge-host-1 https://soc.example.com:8443
    venv\\Scripts\\python scripts\\provision_agent.py list
    venv\\Scripts\\python scripts\\provision_agent.py revoke edge-host-1

After ``add``, restart the SentinelSOC service so the new key is loaded.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.vault import SecretVault, get_vault_path  # noqa: E402
from backend.config import APP_DIR  # noqa: E402

AGENT_KEYS_SECRET = "SENTINEL_AGENT_KEYS"
AGENT_CONFIG_DIR = APP_DIR / "agent_configs"


def load_key_map(vault: SecretVault) -> dict[str, str]:
    raw = vault.get(AGENT_KEYS_SECRET) or "{}"
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return {}


def save_key_map(vault: SecretVault, keymap: dict[str, str]) -> None:
    vault.set_many({AGENT_KEYS_SECRET: json.dumps(keymap, sort_keys=True)})


def generate_key() -> str:
    return "sentinel-agent-" + secrets.token_urlsafe(27)


def write_agent_config(agent_id: str, key: str, server: str) -> Path:
    cfg_dir = APP_DIR / "agent_configs"
    cfg_dir.mkdir(exist_ok=True)
    path = cfg_dir / f"{agent_id}.json"
    payload = {"agent_id": agent_id, "key": key, "server": server, "interval": 15}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def drop_agent_config(agent_id: str) -> None:
    (APP_DIR / "agent_configs" / f"{agent_id}.json").unlink(missing_ok=True)


def cmd_add(args: argparse.Namespace) -> int:
    vault = SecretVault(get_vault_path())
    keymap = load_key_map(vault)
    if args.agent_id in keymap.values():
        sys.exit(f"agent-id '{args.agent_id}' already provisioned (revoke first).")
    key = generate_key()
    keymap[key] = args.agent_id
    save_key_map(vault, keymap)
    cfg = write_agent_config(args.agent_id, key, args.server)
    print(f"provisioned agent '{args.agent_id}'")
    print(f"  vault    : {get_vault_path()}")
    print(f"  key      : {key}")
    print(f"  host cfg : {cfg}")
    print(f"\nOn the agent host:")
    print(f"  python scripts/agent.py --server {args.server} --key \"{key}\" --interval {args.interval}")
    print("\nRestart the SentinelSOC service to load the new key.")


def cmd_list(_: argparse.Namespace) -> None:
    vault = SecretVault(get_vault_path())
    keymap = load_key_map(vault)
    print(f"{'agent-id':<24} {'key (prefix)':<32}")
    for key, agent_id in sorted(keymap.items(), key=lambda kv: kv[1]):
        print(f"{agent_id:<24} {key[:30]}...")
    if not keymap:
        print("(no agent keys in vault)")


def cmd_revoke(args: argparse.Namespace) -> int:
    vault = SecretVault(get_vault_path())
    keymap = load_key_map(vault)
    if args.agent_id in keymap.values():
        key = next(k for k, v in keymap.items() if v == args.agent_id)
        keymap.pop(key, None)
        save_key_map(vault, keymap)
        drop_agent_config(args.agent_id)
        print(f"revoked '{args.agent_id}'")
        return 0
    print(f"agent-id '{args.agent_id}' not found. Current: {list(keymap.values())}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add", help="register a new fleet host")
    add.add_argument("agent_id", help="unique id, e.g. ws-desktop-07")
    add.add_argument("--server", default="http://127.0.0.1:8001", help="central server base URL")
    add.add_argument("--interval", type=int, default=15, help="agent upload interval in seconds")
    add.set_defaults(func=cmd_add)
    sub.add_parser("list", help="show registered agent ids").set_defaults(func=cmd_list)
    revoke = sub.add_parser("revoke", help="remove an agent's credentials")
    revoke.add_argument("agent_id")
    revoke.set_defaults(func=cmd_revoke)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())