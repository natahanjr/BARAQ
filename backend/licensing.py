"""BARAQ License System — tiered licensing with event quotas.

License tiers:
    free        - 100 events/day, 1 department, community support
    standard    - 5,000 events/day, 5 departments, email support
    professional - 50,000 events/day, unlimited departments, priority support
    enterprise  - unlimited, SLA, dedicated support

Usage:
    from backend.licensing import check_license, get_license_info
    allowed = check_license(org_id="library")  # True/False
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from backend.config import APP_DIR

LICENSE_FILE = APP_DIR / "license.json"

TIER_LIMITS = {
    "free":        {"events_per_day": 100,     "departments": 1,  "features": ["basic_detection", "alerts", "dashboard"]},
    "standard":    {"events_per_day": 5_000,   "departments": 5,  "features": ["basic_detection", "alerts", "dashboard", "correlation", "hunting"]},
    "professional": {"events_per_day": 50_000, "departments": -1, "features": ["basic_detection", "alerts", "dashboard", "correlation", "hunting", "ueba", "compliance", "reports"]},
    "enterprise":  {"events_per_day": -1,      "departments": -1, "features": ["basic_detection", "alerts", "dashboard", "correlation", "hunting", "ueba", "compliance", "reports", "api", "sso", "support"]},
}

# ── Default License ──────────────────────────────────────────────────────
DEFAULT_LICENSE = {
    "tier": "free",
    "key": "BARAQ-FREE-2026",
    "org": "default",
    "activated_at": None,
    "expires_at": None,  # None = never expires for free tier
    "features": TIER_LIMITS["free"]["features"],
    "events_per_day": TIER_LIMITS["free"]["events_per_day"],
    "departments": TIER_LIMITS["free"]["departments"],
}


def _hash_key(key: str) -> str:
    """Hash a license key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def load_license() -> dict:
    """Load the current license from disk."""
    if LICENSE_FILE.exists():
        try:
            return json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return DEFAULT_LICENSE.copy()


def save_license(license_data: dict) -> None:
    """Save license to disk."""
    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    LICENSE_FILE.write_text(json.dumps(license_data, indent=2), encoding="utf-8")


def activate_license(key: str, org: str = "default") -> dict:
    """Activate a license key. Returns the license dict or raises ValueError."""
    # Validate key format
    if not key.startswith("BARAQ-"):
        raise ValueError("Invalid license key format. Must start with BARAQ-")

    # Parse tier from key
    parts = key.upper().split("-")
    if len(parts) < 3:
        raise ValueError("Invalid license key format. Expected: BARAQ-TIER-XXXX")

    tier = parts[1].lower()
    if tier not in TIER_LIMITS:
        raise ValueError(f"Unknown tier: {tier}. Valid tiers: free, standard, professional, enterprise")

    tier_config = TIER_LIMITS[tier]

    license_data = {
        "tier": tier,
        "key": key,
        "key_hash": _hash_key(key),
        "org": org,
        "activated_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": None,  # Enterprise could set an expiry
        "features": tier_config["features"],
        "events_per_day": tier_config["events_per_day"],
        "departments": tier_config["departments"],
    }

    save_license(license_data)
    return license_data


def check_license(org_id: str = "default") -> bool:
    """Check if the current license allows operation. Returns True if valid."""
    lic = load_license()

    # Free tier always allowed
    if lic["tier"] == "free":
        return True

    # Check expiry
    if lic.get("expires_at"):
        try:
            expires = datetime.fromisoformat(lic["expires_at"])
            if datetime.now(timezone.utc) > expires:
                return False
        except (ValueError, TypeError):
            pass

    return True


def get_license_info() -> dict:
    """Get current license information."""
    lic = load_license()
    tier_config = TIER_LIMITS.get(lic["tier"], TIER_LIMITS["free"])

    return {
        "tier": lic["tier"],
        "org": lic.get("org", "default"),
        "activated_at": lic.get("activated_at"),
        "expires_at": lic.get("expires_at"),
        "features": lic.get("features", []),
        "limits": {
            "events_per_day": tier_config["events_per_day"],
            "departments": tier_config["departments"],
        },
        "is_valid": check_license(),
    }


def enforce_license(db=None) -> None:
    """Enforce license at startup. Logs warning if invalid, never blocks dev."""
    try:
        info = get_license_info()
        if not info["is_valid"]:
            import logging
            logging.getLogger("baraq").warning(
                "License is invalid/expired (tier=%s). Running in degraded mode.", info["tier"]
            )
    except Exception:
        import logging
        logging.getLogger("baraq").info("No license file found — running in free/dev mode.")


def get_tier_info() -> dict:
    """Get all available tiers and their limits."""
    return {
        tier: {
            "events_per_day": config["events_per_day"],
            "departments": config["departments"],
            "features": config["features"],
        }
        for tier, config in TIER_LIMITS.items()
    }
