# BARAQ - Secrets Rotation Workflow

## Overview

BARAQ stores sensitive credentials in an encrypted vault (`secrets.dat`). This document describes how to rotate secrets on a scheduled basis or after a suspected compromise.

---

## Rotation Schedule

| Secret | Recommended Frequency | Trigger |
|--------|----------------------|---------|
| Admin password | Every 90 days | Compromise, personnel change |
| API keys | Every 90 days | Compromise, personnel change |
| JWT token secret | Every 180 days | Compromise, upgrade |
| Agent keys | Per-agent lifecycle | Agent decommission, compromise |
| TLS certificate | Before expiry | Renewal |

---

## Quick Rotation (All Secrets)

```powershell
# Rotate everything at once
python scripts/rotate_secrets.py all
```

This generates new:
- Admin password (24-char random)
- API keys (admin + analyst)
- JWT token secret (64-char random)

**Restart the backend after rotation.**

---

## Individual Rotation

### Admin Password

```powershell
python scripts/rotate_secrets.py admin-password
```

The new password is printed once. Store it immediately.

After rotation:
1. Log out of the dashboard
2. Log in with the new password
3. The account will prompt for password change on first login

### API Keys

```powershell
python scripts/rotate_secrets.py api-keys
```

Generates new admin and analyst API keys. After rotation:
1. Update any scripts/tools using the old keys
2. Update agent configurations if using API key auth
3. Test API access with the new keys

### JWT Token Secret

```powershell
python scripts/rotate_secrets.py token-secret
```

**Warning:** This invalidates ALL active sessions. Every user must log in again.

---

## Agent Key Rotation

Agent keys are managed separately:

```powershell
# Provision a new agent key
python scripts/provision_agent.py --agent-id <agent-id> --org <org>

# Revoke an agent key (remove from vault)
python -c "
from backend.vault import SecretVault, get_vault_path
v = SecretVault(get_vault_path())
import json
keys = json.loads(v.get('BARAQ_AGENT_KEYS', '{}'))
keys.pop('<agent-key>', None)
v.set('BARAQ_AGENT_KEYS', json.dumps(keys))
"
```

---

## Manual Vault Inspection

```powershell
# List all vault contents (values are masked)
python -c "
from backend.vault import SecretVault, get_vault_path
v = SecretVault(get_vault_path())
for k, val in v.all().items():
    masked = val[:4] + '***' + val[-2:] if len(val) > 6 else '***'
    print(f'  {k}: {masked}')
"
```

---

## Migration from Plaintext

If secrets are still in `.env` (plaintext), migrate them to the vault:

```powershell
python scripts/migrate_secrets.py
```

This:
1. Reads secrets from `.env`
2. Stores them encrypted in `secrets.dat`
3. Comments out the plaintext lines in `.env`
4. The backend reads from vault on next startup

---

## Backup Before Rotation

Always back up the vault before rotating secrets:

```powershell
# Copy vault to backups directory
Copy-Item secrets.dat backups\secrets.dat.bak-$(Get-Date -Format yyyyMMdd)
```

---

## Verification

After rotation, verify the new credentials work:

1. **Health check:** `curl http://localhost:8001/api/health`
2. **Login:** Log in with the new admin password
3. **API key:** Test with `curl -H "X-API-Key: <new-key>" http://localhost:8001/api/dashboard/summary`
4. **Audit chain:** Verify `/api/auth/audit/verify` returns `valid: true`

---

## Emergency Rotation (Suspected Compromise)

If you suspect credentials are compromised:

1. **Immediately** rotate all secrets:
   ```powershell
   python scripts/rotate_secrets.py all
   ```

2. Restart the backend

3. Check the audit log for unauthorized access:
   ```
   GET /api/auth/audit/export?format=json
   ```

4. Review active sessions and revoke if needed

5. Check for backdoor accounts:
   ```
   GET /api/auth/users
   ```

6. Enable MFA enforcement for all admin accounts:
   ```
   BARAQ_ENFORCE_ADMIN_MFA=1
   ```
