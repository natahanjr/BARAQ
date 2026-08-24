# BARAQ - Running as a Windows Service

The SOC must stay up across reboots and analyst logouts. Two supported
mechanisms, both driven by `scripts\run_server.ps1` (sets the production
profile, defaults to port 8001 / 8443 under TLS, writes `logs\server.pid`).

## Install (one command, elevated)

```powershell
scripts\install_service.ps1 install        # NSSM if present, else Task Scheduler
scripts\install_service.ps1 install -Lan    # expose on 0.0.0.0
scripts\install_service.ps1 status
scripts\install_service.ps1 uninstall
```

- **NSSM** (preferred): service auto-start, 5s restart on crash, stdout/stderr
  captured to `logs\nssm.{out,err}.log`. Get NSSM from nssm.cc (drop
  `nssm.exe` on PATH or at `C:\tools\nssm\`).
- **Task Scheduler fallback**: an AtStartup task running as SYSTEM with
  highest privileges; no extra tooling required. Less observable than NSSM.

The script re-launches itself elevated if you forget to run as admin.

## Before you install

1. `scripts\db_backup.py backup --keep 14` - never install over an unbacked DB.
2. Decide the bind: keep `127.0.0.1` and put a reverse proxy (see
   `documentation\tls_https.md`) in front for real exposure, OR use `-Lan`
   together with `start.bat secure`'s certs for a self-signed LAN deployment.
3. If running the service as SYSTEM, make sure the vault (`secrets.dat`,
   DPAPI user-scoped) is readable by that account - if the server starts as
   your own user via the logon task instead, secrets resolve normally.

## Ops

```powershell
scripts\install_service.ps1 status          # service/task state + pid + port
net start BARAQ | net stop BARAQ  (NSSM mode)
schtasks /End /TN BARAQ                (task mode)
```

Logs: `logs\server.err.log` (app), `logs\nssm.err.log` (NSSM), or the
baraq.log written by `run_server.py`.

## Upgrades

```powershell
scripts\db_backup.py backup --keep 14
scripts\install_service.ps1 uninstall
git pull (or redeploy the package)
venv\Scripts\python scripts\migrate_db.py     # schema migrations, if any
scripts\install_service.ps1 install
```

## Verification after install

```powershell
Invoke-RestMethod http://127.0.0.1:8001/api/health   # expect status:"ok"
# Reboot the box once, confirm the SOC comes back without logon.
```