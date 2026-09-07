"""Secrets rotation utility for BARAQ.

Usage:
    python scripts/rotate_secrets.py admin-password    # Rotate admin password
    python scripts/rotate_secrets.py api-keys          # Rotate API keys
    python scripts/rotate_secrets.py token-secret      # Rotate JWT token secret
    python scripts/rotate_secrets.py all               # Rotate all secrets
"""
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.vault import SecretVault, get_vault_path


def rotate_admin_password(vault: SecretVault) -> str:
    """Generate and store a new admin password."""
    new_password = secrets.token_urlsafe(24)
    vault.set("BARAQ_ADMIN_PASSWORD", new_password)
    return new_password


def rotate_api_keys(vault: SecretVault) -> dict:
    """Generate new API keys."""
    keys = {
        f"baraq-{secrets.token_hex(8)}": "admin",
        f"baraq-{secrets.token_hex(8)}": "analyst",
    }
    import json
    vault.set("BARAQ_API_KEYS", json.dumps(keys))
    return keys


def rotate_token_secret(vault: SecretVault) -> str:
    """Generate new JWT token secret."""
    new_secret = secrets.token_urlsafe(64)
    vault.set("BARAQ_TOKEN_SECRET", new_secret)
    return new_secret


def main():
    if len(sys.argv) < 2:
        print("Usage: python rotate_secrets.py <admin-password|api-keys|token-secret|all>")
        sys.exit(1)
    
    action = sys.argv[1]
    vault_path = get_vault_path()
    vault = SecretVault(vault_path)
    
    print(f"Vault: {vault_path}")
    print()
    
    if action in ("admin-password", "all"):
        pwd = rotate_admin_password(vault)
        print(f"[OK] Admin password rotated: {pwd}")
    
    if action in ("api-keys", "all"):
        keys = rotate_api_keys(vault)
        print(f"[OK] API keys rotated: {keys}")
    
    if action in ("token-secret", "all"):
        secret = rotate_token_secret(vault)
        print(f"[OK] Token secret rotated: {secret[:8]}...")
    
    print("\nRestart the backend to apply changes.")


if __name__ == "__main__":
    main()
