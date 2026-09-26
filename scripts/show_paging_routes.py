"""Show which channels each severity reaches, for the configured floors.

Read-only diagnostic. Run it after changing the paging settings:
    venv\\Scripts\\python scripts\\show_paging_routes.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import backend.notify as n  # noqa: E402

SEVERITIES = ("low", "medium", "high", "critical")


def main() -> int:
    print(f"email/toast floor : {n.NOTIFY_MIN_SEVERITY}")
    print(f"telegram floor    : {n._CHANNEL_MIN_SEVERITY['telegram']}")
    print(f"webhook floor     : {n._CHANNEL_MIN_SEVERITY['webhook']}")
    print()
    print(f"{'severity':<10}{'telegram':<12}{'email':<10}{'webhook':<10}{'toast'}")
    for sev in SEVERITIES:
        print(
            f"{sev:<10}"
            f"{str(n._wanted(sev, 'telegram')):<12}"
            f"{str(n._wanted(sev, 'email')):<10}"
            f"{str(n._wanted(sev, 'webhook')):<10}"
            f"{n._wanted(sev, 'toast')}"
        )
    print()
    print("configured channels:")
    for name in ("webhook", "email", "telegram", "toast"):
        print(f"  {name:<10} {'yes' if n._configured(name) else 'no (not configured)'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
