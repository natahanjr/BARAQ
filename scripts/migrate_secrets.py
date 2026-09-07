"""Migrate plaintext credentials from .env to DPAPI vault.

Run once to encrypt secrets:
    python scripts/migrate_secrets.py

After migration, remove plaintext values from .env.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.vault import SecretVault, get_vault_path


def main():
    vault_path = get_vault_path()
    print(f"Vault path: {vault_path}")
    
    vault = SecretVault(vault_path)
    
    # Secrets to migrate from .env
    secrets_to_migrate = {
        "BARAQ_DATABASE_URL": "postgresql+psycopg://postgres:password@127.0.0.1:55432/baraq",
    }
    
    migrated = 0
    for name, value in secrets_to_migrate.items():
        if vault.has(name):
            print(f"  [SKIP] {name} already in vault")
        else:
            vault.set(name, value)
            print(f"  [OK] {name} migrated to vault")
            migrated += 1
    
    print(f"\nMigrated {migrated} secrets to {vault_path}")
    print("Next steps:")
    print("1. Remove plaintext values from .env")
    print("2. Restart the backend")


if __name__ == "__main__":
    main()
