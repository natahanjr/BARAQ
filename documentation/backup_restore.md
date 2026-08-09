# SentinelSOC - Backup & Restore Runbook

Owner: SentinelSOC operator. Applies to PostgreSQL fleet deployments (default
for deployments) and the SQLite development profile.

## Tooling

One script covers everything:

    venv\Scripts\python scripts\db_backup.py backup  [--dir backups] [--keep 10] [--encrypt]
    venv\Scripts\python scripts\db_backup.py list    [--dir backups]
    venv\Scripts\python scripts\db_backup.py verify  <archive> [--dir backups]
    venv\Scripts\python scripts\db_backup.py restore <archive> [--yes] [--target URL]

* Target database: `SENTINEL_DATABASE_URL` (from `.env`/environment); override
  per-invocation with `--target`.
* PostgreSQL binaries must be reachable (`SENTINEL_PG_BIN`, PATH, or the
  embedded cluster bin dir). The script aborts with a clear message if
  `pg_dump`/`pg_restore` are missing.
* Archives land in `./backups/` (override with `--dir`). Format: a SHA-256
  manifest sidecar (`<archive>.sha256`) is written for every archive; `list`
  flags any archive whose digest does not match as `MISMATCH`.

## Creating a backup

```bash
venv\Scripts\python scripts\db_backup.py backup --keep 14
venv\Scripts\python scripts\db_backup.py backup --keep 14 --encrypt   # at-rest confidentiality
```

Notes:
- PostgreSQL: `pg_dump -Fc` (consistent snapshot; safe while the app runs;
  the application never needs to be stopped for *backups*).
- SQLite: the file is checkpointed before copying; keep the app stopped for a
  fully consistent copy.
- `--encrypt` wraps the archive with AES-256-GCM under the DPAPI vault master
  key. Decryption therefore only works on a machine whose vault holds the same
  key stream and under the same Windows user - plan your restore host
  accordingly.
- Retention: only the newest `--keep` archives (plus manifests) are retained;
  older ones are pruned and reported.

## Scheduling a daily backup (Windows)

```powershell
schtasks /Create /TN "SentinelSOC DB Backup" /SC DAILY /ST 03:00 `
  /TR "F:\My Project\SentinelSOC\venv\Scripts\python.exe F:\My Project\SentinelSOC\scripts\db_backup.py backup --keep 14 --encrypt"
```

For Linux, use a cron entry running the same command.

## Verifying a backup

```bash
venv\Scripts\python scripts\db_backup.py verify <archive>
venv\Scripts\python scripts\db_backup.py list         # verifies all archives
```

A `verified` status proves archive bytes match the manifest digest. **Verify
backups regularly (weekly) and before any restore.**

## Restoring

1. **Stop the SentinelSOC service** (scheduler writes constantly; a running
   app will both overwrite restored rows and fight `pg_restore`):

   ```powershell
   Get-NetTCPConnection -LocalPort 8001 -State Listen | ForEach-Object {
     Stop-Process -Id $_.OwningProcess -Force
   }
   ```

2. Pick the archive (prefer the newest verified one):

   ```bash
   venv\Scripts\python scripts\db_backup.py verify <archive>
   ```

3. Restore (destructive - replaces target DB contents):

   ```bash
   venv\Scripts\python scripts\db_backup.py restore <archive> --yes
   ```

   For a scratch-database rehearsal (recommended before any destructive
   restore):

   ```bash
   createdb -h 127.0.0.1 -p 55432 -U postgres sentinel_scratch
   venv\Scripts\python scripts\db_backup.py restore <archive> --yes `
     --target postgresql+psycopg://postgres@127.0.0.1:55432/sentinel_scratch
   ```

4. Start the service again; validate counts and audit chain
   (`/api/audit/verify` should report chain valid).

Notes:
- The script refuses to run without `--yes` and refuses archives whose
  manifest does not match or is missing (tamper / partial-copy guard).
- Encrypted archives: decryption failure (wrong host, different vault key)
  aborts before any database is touched.

## RPO / RTO expectations

- Footprint: ~150 MB per archive at ~40 days of simulated events (your fleet
  size will differ). Compressed custom format (`-Fc -Z9`).
- Restore of the reference environment took under a minute on localhost I/O
  for ~12k events, ~2k entity nodes and 2 users. Plan the runbook test once
  per quarter on the production-sized database.
