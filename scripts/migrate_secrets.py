"""Migrate plaintext credentials from .env to DPAPI vault.

Run once to encrypt secrets:
    python scripts/migrate_secrets.py

After migration, plaintext values are commented out from .env.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.vault import SecretVault, get_vault_path

_VAULT_SECRETS = (
    "BARAQ_DATABASE_URL",
    "BARAQ_ADMIN_PASSWORD",
    "BARAQ_API_KEYS",
    "BARAQ_TOKEN_SECRET",
    "BARAQ_AGENT_KEYS",
    "BARAQ_AI_API_KEY",
    "BARAQ_ENCRYPTION_KEY",
    "BARAQ_SMTP_PASSWORD",
    "BARAQ_TELEGRAM_BOT_TOKEN",
    "BARAQ_LDAP_BIND_PASSWORD",
    "BARAQ_OIDC_CLIENT_SECRET",
    "BARAQ_ABUSEIPDB_KEY",
    "BARAQ_OTX_KEY",
    "BARAQ_VT_KEY",
    "BARAQ_SHODAN_KEY",
    "BARAQ_JIRA_API_TOKEN",
    "BARAQ_SERVICENOW_PASSWORD",
)


def _load_dotenv(path):
    values = {}
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        return values
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _comment_out_in_env(env_path, keys):
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.partition("=")[0].strip()
            if key in keys:
                new_lines.append(f"# [MIGRATED TO VAULT] {line}")
                continue
        new_lines.append(line)
    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def main():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    vault_path = get_vault_path()

    print(f"Vault path: {vault_path}")
    print(f"Env path:  {env_path}")
    print()

    vault = SecretVault(vault_path)
    env_values = _load_dotenv(env_path)

    migrated = 0
    already_in_vault = 0
    missing = []

    for name in _VAULT_SECRETS:
        env_value = env_values.get(name, "")
        vault_value = vault.get(name)

        if vault_value:
            print(f"  [SKIP] {name} already in vault")
            already_in_vault += 1
            continue

        if env_value:
            vault.set(name, env_value)
            print(f"  [OK]   {name} migrated to vault")
            migrated += 1
        else:
            missing.append(name)
            print(f"  [WARN] {name} not found in .env or vault")

    if migrated > 0:
        _comment_out_in_env(env_path, [n for n in _VAULT_SECRETS if env_values.get(n)])

    print(f"\nSummary: {migrated} migrated, {already_in_vault} already in vault, {len(missing)} missing")
    print(f"Vault: {vault_path}")

    if missing:
        print(f"\nMissing secrets (set via vault or .env):")
        for name in missing:
            print(f"  - {name}")

    print("\nNext steps:")
    print("1. Verify vault: python -c \"from backend.vault import SecretVault, get_vault_path; v=SecretVault(get_vault_path()); print(v.all())\"")
    print("2. Restart the backend")


if __name__ == "__main__":
    main()
