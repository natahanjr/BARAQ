# BARAQ — Backup & Restore (PostgreSQL)



Authoritative database backup/restore for the central console. One script,

`scripts/db_backup.py`, handles both directions; archives are verified

cryptographically before any restore is allowed.



---



> **Restoring is the part you must rehearse.** A backup that has never been
> restored is a hypothesis. Restore the newest archive into a scratch database
> before trusting it - done on this deployment, it matched row for row:
>
> ```
> venv\Scripts\python scripts\db_backup.py list
> psql -h 127.0.0.1 -U postgres -d postgres -c "CREATE DATABASE baraq_restore_drill;"
> venv\Scripts\python scripts\db_backup.py restore <archive> --yes ^
>   --target postgresql+psycopg://postgres:...@127.0.0.1:55432/baraq_restore_drill
> ```
>
> Encrypted (`.enc`) archives restore the same way; the key comes from the
> DPAPI vault, so rehearse as the same Windows account that would need to
> restore during an incident.

### The client tools are found automatically

`pg_dump` / `pg_restore` no longer need `BARAQ_PG_BIN`. The script probes the
environment variable, `PATH`, then the layouts this project actually produces:
`<project>/pg/bin`, `<project>/pg/pgsql/bin`, `<project>/dist/pg/bin`
(including the nested `bin/bin`), `%LOCALAPPDATA%\BARAQ\postgres\bin`, and
`C:\Program Files\PostgreSQL\<version>\bin`. This matters because a scheduled
task runs with the service account's PATH, which normally has no PostgreSQL on
it - the 03:00 backup previously failed silently.

### Unattended backups

```
powershell -ExecutionPolicy Bypass -File scripts\install_backup_task.ps1 -Time 03:00
```

Registers `BARAQ-DB-Backup` (daily, encrypted, keeps 14). Verify it really ran
instead of trusting the registration:

```
Start-ScheduledTask -TaskName 'BARAQ-DB-Backup'
(Get-ScheduledTaskInfo -TaskName 'BARAQ-DB-Backup').LastTaskResult   # 0 = success
```

---
## 1. What gets backed up



| Item | How | Where |

|------|-----|-------|

| PostgreSQL database (`events`, `alerts`, `users`, `verdicts`, graph, ...) | `pg_dump -Fc -Z 9 --no-owner` | `backups\baraq_postgres_<TS>.dump` |

| Integrity manifest | SHA-256 of the archive | `<archive>.sha256` sidecar |

| Secrets vault (`secrets.dat`) | Windows DPAPI file; **copy separately** | see §5 |



Plain `dump` archives are written unencrypted; add `--encrypt` to wrap each

archive with AES-256-GCM under the DPAPI vault master key (`backend.crypto`).



## 2. One-off backup



```powershell

venv\Scripts\python scripts\db_backup.py backup --encrypt --keep 14

```



- `--keep N` prunes everything older than the newest N archives.

- `--dir DIR` overrides the default `backups\` folder.



Verify the archive was written and passes its manifest:



```powershell

venv\Scripts\python scripts\db_backup.py list     # verified / MISMATCH column

venv\Scripts\python scripts\db_backup.py verify <archive>.dump

```



## 3. Automated daily backups (recommended)



Install a daily Windows scheduled task (elevated shell):



```powershell

powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_backup_task.ps1 -Time 03:00

```



- Default runs `backup --encrypt --keep 14` every day at 03:00.

- Confirm it fires: `Get-ScheduledTaskInfo -TaskName BARAQ-DB-Backup`

- Remove later: `... install_backup_task.ps1 -Remove`



## 4. Restore drill (tested procedure)



Run this on a **test copy** of the cluster before you ever need it in anger.



1. Stop the console so no writer holds the database:

   ```powershell

   Stop-Service BARAQ-Server   # or kill the uvicorn process

   ```

2. Restore (destructive — refuses without `--yes`):

   ```powershell

   venv\Scripts\python scripts\db_backup.py restore baraq_postgres_<TS>.dump --yes

   ```

   `pg_restore --clean --if-exists` rebuilds the target; the manifest is

   checked first, so a tampered or missing-archive restore aborts before any

   data is touched.

3. Verify the restore:

   ```powershell

   venv\Scripts\python scripts\db_backup.py list   # archive still verified

   # app-level check:

   venv\Scripts\python -m pytest tests/test_audit_chain.py -q

   ```

4. Restart the console and confirm dashboards + `/api/health` return 200.



**Expected outcome:** `/api/events` totals match the pre-backup numbers and

the audit chain verifies (`/api/auth/audit/verify` returns `valid: true`).



## 5. Secrets vault (separate from the database)



`secrets.dat` (DPAPI-encrypted agent keys, API keys, session secret) is

**machine-bound** — it cannot be decrypted on another machine. Back it up

together with the database:



```powershell

Copy-Item certs\..\secrets.dat backups\secrets.dat.bak   # after console stop

```



On a rebuild: copy `secrets.dat` back to the project root **before** first

startup, or re-key everything with `scripts\provision_*` / the user tooling.



## 6. Retention & capacity



- `--keep 14` at one archive/day — 14 archives; size ~ DB size after comp.

- Monitor `backups\` free space; PostgreSQL itself stays on its own volume.

- Schedule a quarterly restore-to-test-copy drill and log its outcome.

