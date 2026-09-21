# BARAQ - Firewall Exclusions

## Windows Firewall Rules

When running BARAQ in LAN mode (`start.bat lan` or `start.bat secure lan`), the following ports must be opened:

### Required Ports

| Port | Protocol | Direction | Purpose |
|------|----------|-----------|---------|
| 8001 | TCP | Inbound | BARAQ API (HTTP) |
| 8443 | TCP | Inbound | BARAQ API (HTTPS/TLS) |
| 5432 | TCP | Inbound | PostgreSQL (only if remote agents connect directly) |
| 5173 | TCP | Inbound | Frontend dev server (dev mode only) |

### PowerShell - Add Firewall Rules (Run as Administrator)

```powershell
# HTTP API
New-NetFirewallRule -DisplayName "BARAQ API (HTTP)" -Direction Inbound -Protocol TCP -LocalPort 8001 -Action Allow -Profile Domain,Private

# HTTPS API
New-NetFirewallRule -DisplayName "BARAQ API (HTTPS)" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow -Profile Domain,Private

# PostgreSQL (only if remote agents connect directly to DB)
# New-NetFirewallRule -DisplayName "BARAQ PostgreSQL" -Direction Inbound -Protocol TCP -LocalPort 5432 -Action Allow -Profile Domain,Private -RemoteAddress 192.168.1.0/24
```

### Remove Firewall Rules

```powershell
Remove-NetFirewallRule -DisplayName "BARAQ API (HTTP)"
Remove-NetFirewallRule -DisplayName "BARAQ API (HTTPS)"
```

## Security Notes

- Only open ports on **Domain** and **Private** network profiles, never Public.
- Restrict PostgreSQL (5432) to specific agent subnets, not the entire LAN.
- If using a reverse proxy (Caddy/nginx), only the proxy port needs to be open.
- The backend binds to `0.0.0.0` in LAN mode, so firewall is the primary network control.
