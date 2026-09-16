"""Seed BARAQ with departments and their agent hosts.

Creates tenant organizations for each department, generates unique API keys,
and outputs deployment commands for each host.

Usage:
    venv\\Scripts\\python scripts\\seed_departments.py --server http://localhost:8001
    venv\\Scripts\\python scripts\\seed_departments.py --server https://soc.example.com:8443 --orgs "ict,library,finance"
    venv\\Scripts\\python scripts\\seed_departments.py --dry-run  # preview without changes
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

# ── Default Department Layout ────────────────────────────────────────────
DEFAULT_DEPARTMENTS = {
    "ict": {
        "name": "ICT Department",
        "hosts": ["srv-ict-01", "ws-ict-01", "ws-ict-02"],
        "description": "IT servers and admin workstations",
    },
    "library": {
        "name": "Library",
        "hosts": ["ws-lib-01", "ws-lib-02", "ws-lib-03", "ws-lib-04"],
        "description": "OPAC terminals and staff PCs",
    },
    "finance": {
        "name": "Finance Department",
        "hosts": ["ws-fin-01", "ws-fin-02", "ws-fin-03", "ws-fin-04"],
        "description": "Accounting workstations",
    },
    "registrar": {
        "name": "Registrar",
        "hosts": ["ws-reg-01", "ws-reg-02", "ws-reg-03"],
        "description": "Student records systems",
    },
    "hr": {
        "name": "Human Resources",
        "hosts": ["ws-hr-01", "ws-hr-02"],
        "description": "Personnel records",
    },
    "admissions": {
        "name": "Admissions",
        "hosts": ["ws-adm-01", "ws-adm-02", "ws-adm-03", "ws-adm-04"],
        "description": "Application processing",
    },
    "exams": {
        "name": "Examinations",
        "hosts": ["ws-exm-01", "ws-exm-02", "ws-exm-03"],
        "description": "Exam systems",
    },
    "maintenance": {
        "name": "Maintenance",
        "hosts": ["ws-mnt-01", "ws-mnt-02"],
        "description": "Facility systems",
    },
    "admin": {
        "name": "Administration",
        "hosts": ["ws-adm-01", "ws-adm-02", "ws-adm-03"],
        "description": "Management offices",
    },
    "vc": {
        "name": "Vice Chancellor",
        "hosts": ["ws-vc-01", "ws-vc-02"],
        "description": "Executive offices",
    },
}

MANIFEST_DIR = APP_DIR / "agent_configs"


def _make_key(dept: str, host: str) -> str:
    """Generate a deterministic agent key: baraq-<dept>-<host>."""
    return f"baraq-{dept}-{host}"


def _agent_cmd(server: str, key: str, dept: str, interval: int, tls_cert: str) -> str:
    ca = f" --tls-ca {tls_cert}" if tls_cert else ""
    return (
        f'powershell -ExecutionPolicy Bypass -File scripts/install_agent.ps1 '
        f'-Server {server} -Key "{key}" -Org {dept} -Interval {interval}{ca}'
    )


def seed(
    server: str,
    orgs: list[str] | None = None,
    tls_cert: str = "",
    interval: int = 15,
    dry_run: bool = False,
) -> dict:
    """Seed departments and return the manifest."""
    departments = DEFAULT_DEPARTMENTS
    if orgs:
        departments = {k: v for k, v in DEFAULT_DEPARTMENTS.items() if k in orgs}

    manifest: dict = {"server": server, "departments": {}}
    all_commands: list[dict] = []

    for dept, info in departments.items():
        dept_entry = {
            "name": info["name"],
            "description": info["description"],
            "hosts": {},
        }
        for host in info["hosts"]:
            key = _make_key(dept, host)
            cmd = _agent_cmd(server, key, dept, interval, tls_cert)
            dept_entry["hosts"][host] = {
                "key": key,
                "command": cmd,
            }
            all_commands.append({"department": dept, "host": host, "key": key, "command": cmd})
        manifest["departments"][dept] = dept_entry

    return manifest, all_commands


def print_manifest(manifest: dict, commands: list[dict]) -> None:
    """Pretty-print the deployment manifest."""
    print()
    print("=" * 70)
    print("  BARAQ DEPARTMENT SEEDING MANIFEST")
    print("=" * 70)
    print(f"  Server: {manifest['server']}")
    print(f"  Departments: {len(manifest['departments'])}")
    total_hosts = sum(len(d['hosts']) for d in manifest['departments'].values())
    print(f"  Total Endpoints: {total_hosts}")
    print("=" * 70)

    for dept, info in manifest["departments"].items():
        print()
        print(f"  [{dept.upper()}] {info['name']}")
        print(f"  {info['description']}")
        print(f"  Hosts: {len(info['hosts'])}")
        print("-" * 70)
        for host, details in info["hosts"].items():
            print(f"    {host}")
            print(f"      Key:     {details['key']}")
            print(f"      Command: {details['command']}")
        print()

    print("=" * 70)
    print("  DEPLOYMENT INSTRUCTIONS")
    print("=" * 70)
    print()
    print("  1. Copy install_agent.ps1 to a network share accessible by all endpoints")
    print("  2. For each host, run the command listed above on that laptop")
    print("  3. The agent will install, register, and start automatically")
    print("  4. Verify in the BARAQ dashboard: System > Connected Endpoints")
    print()
    print("  QUICK START (copy-paste for each department):")
    print("-" * 70)

    # Group by department for quick copy
    for dept, info in manifest["departments"].items():
        print(f"\n  # {info['name']}")
        for host, details in info["hosts"].items():
            print(f"  # On {host}:")
            print(f"  {details['command']}")
    print()


def save_manifest(manifest: dict, path: Path) -> None:
    """Save manifest to JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n  Manifest saved to: {path}")


def main():
    parser = argparse.ArgumentParser(description="Seed BARAQ departments")
    parser.add_argument("--server", default="http://localhost:8001", help="BARAQ server URL")
    parser.add_argument("--orgs", default=None, help="Comma-separated org IDs (default: all)")
    parser.add_argument("--tls-cert", default="", help="TLS certificate path")
    parser.add_argument("--interval", type=int, default=15, help="Agent interval (seconds)")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    parser.add_argument("--output", default=None, help="Output manifest JSON path")
    args = parser.parse_args()

    orgs = args.orgs.split(",") if args.orgs else None
    manifest, commands = seed(args.server, orgs, args.tls_cert, args.interval, args.dry_run)

    print_manifest(manifest, commands)

    if not args.dry_run:
        output = Path(args.output) if args.output else MANIFEST_DIR / "departments-manifest.json"
        save_manifest(manifest, output)
        print("\n  NOTE: Restart the BARAQ service so new agent keys are loaded.")
    else:
        print("\n  [DRY RUN] No changes saved. Remove --dry-run to apply.")


if __name__ == "__main__":
    main()
