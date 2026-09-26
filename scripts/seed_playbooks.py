"""Seed starter automation playbooks so SOAR has something to run.

Idempotent: a playbook with the same name is left alone, so re-running is safe.

The defaults are deliberately non-destructive. Containment actions (block_ip,
kill_process, quarantine, isolate, disable_account) are still simulated while
BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0, and even with it enabled they ship
DISABLED so an operator turns them on deliberately:

    venv\\Scripts\\python scripts\\seed_playbooks.py                 # safe set
    venv\\Scripts\\python scripts\\seed_playbooks.py --with-soar     # + containment (disabled)
    venv\\Scripts\\python scripts\\seed_playbooks.py --list
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.automation.playbooks import validate_playbook  # noqa: E402
from backend.database.connection import SessionLocal  # noqa: E402
from backend.database.models import AutomationPlaybook  # noqa: E402

#: Safe, read-mostly / ticket-style playbooks. These are what a new deployment
#: should start with: they demonstrate the engine end to end and cannot change
#: the state of an endpoint.
STARTER_PLAYBOOKS: list[dict] = [
    {
        "name": "Critical alerts open an incident",
        "description": (
            "Any critical alert immediately raises an incident so the on-call "
            "analyst has a tracking record with the evidence attached."
        ),
        "triggers": {"severity": ["critical"]},
        "actions": [{"action": "create_incident"}],
        "enabled": True,
    },
    {
        "name": "Credential-access alerts open an incident",
        "description": (
            "Brute force, credential dumping and related Credential Access "
            "detections become incidents even when the severity is only high."
        ),
        "triggers": {"tactics": ["Credential Access"], "severity": ["high", "critical"]},
        "actions": [{"action": "create_incident"}],
        "enabled": True,
    },
    {
        "name": "Notify on every high or critical alert",
        "description": (
            "Sends the standard out-of-band notification for the alert tier "
            "that pages humans. Useful as a template and as a smoke test."
        ),
        "triggers": {"severity": ["high", "critical"]},
        "actions": [{"action": "notify"}],
        "enabled": True,
    },
    {
        "name": "Ransomware / impact alerts get an incident and a page",
        "description": (
            "Impact-tier detections (ransomware, destructive commands) are "
            "escalated immediately rather than waiting for triage."
        ),
        "triggers": {"tactics": ["Impact"], "severity": ["high", "critical"]},
        "actions": [{"action": "create_incident"}, {"action": "notify"}],
        "enabled": True,
    },
]

#: Containment playbooks. Created DISABLED: an operator enables them only after
#: rehearsing the action, because these touch endpoint state.
SOAR_PLAYBOOKS: list[dict] = [
    {
        "name": "Block the source IP on high-severity recon (CONTAINMENT)",
        "description": (
            "Blocks the offending source address on the endpoint. Ships "
            "disabled. Simulated while destructive SOAR actions are off, and "
            "reversible with the unblock_ip action."
        ),
        "triggers": {"rules": ["network_recon", "c2_beacon"], "severity": ["high", "critical"]},
        "actions": [{"action": "block_ip"}],
        "enabled": False,
    },
    {
        "name": "Quarantine suspected malware (CONTAINMENT)",
        "description": (
            "Moves a suspected malicious file to quarantine. Ships disabled - "
            "this changes files on a live endpoint."
        ),
        "triggers": {"rules": ["malware_file", "masquerading"], "severity": ["high", "critical"]},
        "actions": [{"action": "quarantine"}],
        "enabled": False,
    },
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed BARAQ automation playbooks")
    ap.add_argument("--with-soar", action="store_true", help="also add containment playbooks (disabled)")
    ap.add_argument("--list", action="store_true", help="print what would be seeded and exit")
    args = ap.parse_args()

    wanted = list(STARTER_PLAYBOOKS) + (list(SOAR_PLAYBOOKS) if args.with_soar else [])
    if args.list:
        for p in wanted:
            state = "enabled" if p["enabled"] else "disabled"
            print(f"{p['name']}  [{state}]")
        return 0

    db = SessionLocal()
    created = skipped = 0
    try:
        for spec in wanted:
            triggers, actions = validate_playbook(spec["triggers"], spec["actions"])
            exists = db.query(AutomationPlaybook).filter(
                AutomationPlaybook.name == spec["name"]
            ).first()
            if exists:
                skipped += 1
                continue
            db.add(
                AutomationPlaybook(
                    name=spec["name"],
                    description=spec["description"],
                    triggers=triggers,
                    actions=actions,
                    enabled=spec["enabled"],
                )
            )
            created += 1
        db.commit()
    finally:
        db.close()

    print(f"playbooks created: {created}, already present: {skipped}")
    if not args.with_soar:
        print("Containment playbooks were NOT added. Re-run with --with-soar to add them (they stay disabled).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
