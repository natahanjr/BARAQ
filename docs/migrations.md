# BARAQ - Schema Migrations (Alembic)



Alembic controls the database schema going forward. It reads the exact same

connection string as the application (`BARAQ_DATABASE_URL`), so there is

never a second place to configure the database.

> **Verified on a fresh database, 2026-09.** This path was broken: the baseline
> revision's `revision =` id did not match the `down_revision` declared by the
> additive-columns revision, so `alembic upgrade head` died with
> `KeyError: '0001_baseline'` and **no new deployment could be migrated at
> all**. `scripts\migrate_db.py` is covered by
> `tests/test_migrations.py::test_migrations_baseline_bootstraps_fresh_postgres`,
> which creates a throwaway database and runs the real upgrade end to end, so a
> broken chain fails the suite rather than a production deploy.

## Quick reference



```bash

# Apply everything needed on the configured database:

venv\Scripts\python scripts\migrate_db.py



# Deployments that predate Alembic (schema already matches the models):

venv\Scripts\python scripts\migrate_db.py --stamp



# Author a migration after editing backend/database/models.py:

venv\Scripts\python -m alembic revision --autogenerate -m "describe change"

#   review alembic/versions/<rev>_*.py, then: venv\Scripts\python scripts\migrate_db.py



# See the current state:

venv\Scripts\python -m alembic current

```



The raw Alembic CLI requires `BARAQ_DATABASE_URL` to be exported in the

shell (the project `.env` does not set it; the dev stack does so inline).



## Additive migrations are idempotent

`002_additive_columns.py` replays the same column set the application applies

at startup, using `ADD COLUMN IF NOT EXISTS` semantics, and **skips tables that

do not exist** on the target database. A fresh install (where `create_all` only

creates what the models declare) and a long-lived install therefore both

upgrade cleanly, and re-running the upgrade is harmless.

Columns introduced by the 2026-09 pass: `users.sessions_valid_after`,

`reports.org`, `assistant_messages.user_id`, `agent_commands.sha256`.

## Adding a migration

1. Edit `backend/database/models.py`.
2. `venv\Scripts\python -m alembic revision --autogenerate -m "describe change"`
3. **Read the generated file.** The chain must be intact (each `down_revision`
   matches the previous revision's `revision` id) and every `ADD COLUMN` must be
   guarded, or a fresh database will fail exactly as it did in September.
4. `venv\Scripts\python scripts\migrate_db.py`
5. Add a test that runs the upgrade against a throwaway database
   (`tests/test_migrations.py` is the pattern).
## How the baseline works



- Revision `0001_baseline` replays the full model metadata with

  create-if-missing semantics. On a brand-new database, `migrate_db.py`

  (i.e. `alembic upgrade head`) builds every table and index the models

  declare.

- Existing deployments skip DDL and run `--stamp`: their schema was created

  by `init_db()` and matches the metadata.

- `init_db()` still runs at every start: it re-runs `create_all`

  (harmless), enforces the additive-column shims and analytic indexes that

  are maintained outside the ORM - both mechanisms are compatible.



## Rules of the road



1. Never edit a migration that already ran somewhere; add a new one.

2. After any change to `backend/database/models.py`, autogenerate a revision

   and review it before committing (rename/drop-of-critical-data detection;

   autogenerate is a starting point, not an authority).

3. `tests/test_migrations.py` boots a fresh SQLite database through the full

   migration chain in CI - keep it green when touching revisions.

4. Rolling back: Alembic only knows how to undo migrations it created. The

   baseline's downgrade is a no-op by design (pre-Alembic deployments).



## Deployment checklist



1. `venv\Scripts\python scripts\db_backup.py backup --keep 14` (pre-migration

   backup; see `documentation/backup_restore.md`).

2. Stop the service, run `scripts\migrate_db.py`, start the service.

3. `alembic current` == head; read the app logs for `Database initialised`.



The `0001_baseline` version-stamped live reference env on 2026-08-08; you're

current if `alembic current` reports `ac765816b06d (head)`.

