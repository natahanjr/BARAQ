# Environment Separation (Phase 0.7)

The v2 rebuild must never experiment directly against the v1 production
database.

## Environments

```text
BARAQ
├── development     -> synthetic/test telemetry; scratch DB (baraq_scratch_*)
├── evaluation      -> ground-truth datasets; disposable DB (baraq_test)
└── production      -> real telemetry; the live DB (sentinel, port 55432)
```

## Rules

1. `BARAQ_ENV` selects the environment. `run_server.ps1` defaults to
   `development`; set `BARAQ_ENV=production` explicitly for hardened runs.
2. Development/evaluation code runs against `baraq_scratch_*` / `baraq_test`
   databases only. Production connection (`postgresql+psycopg://postgres@
   127.0.0.1:55432/sentinel`) is read-only for the v2 workstream.
3. The v1 production DB is frozen: no new detection rules, no threshold
   tuning, no alert/incident generation changes (Phase 0.1).
4. Dataset exports live under `backups/2026-08-17-baseline/` — the
   evaluation harness reads from there, not from the live tables.

## Enforcement (code, not just this document)

The v1 app itself runs with `BARAQ_ENV=development` against the production
DB (`sentinel`) — that is v1's own design and stays untouched (production
profile would refuse v1's dev keys). What is enforced for **v2**:

| Layer | Guard |
|-------|-------|
| Config | `TELEMETRY_V2_ENABLED` is forced `False` when the configured DB is `sentinel` — even if `BARAQ_ENV` is unset (defaults to development). See `backend/config.py`. |
| Pipeline | `ingest()` raises unless the configured DB is not the production DB name. `backend/telemetry/ingestion/pipeline.py`. |
| API | `/api/v2/telemetry/*` returns `{"status": "disabled"}` whenever the gate is off. |
| Seed script | `scripts/dev_seed_telemetry.py` refuses `sentinel`, `baraq_test`, and `BARAQ_ENV=production`. |

Regression tests cover the first three: `tests/test_telemetry_v2.py`.

## Baseline snapshot

| Asset | Location |
|-------|----------|
| Full DB dump (custom format) | `backups/2026-08-17-baseline/database/sentinel.dump` |
| Analytical CSVs (25 tables, 5,439 rows) | `backups/2026-08-17-baseline/<domain>/` |
| ML model bundle + meta | `backups/2026-08-17-baseline/ml/` |
| Sigma rules (2,518) + correlation rules + python rules | `backups/2026-08-17-baseline/rules/` |
| Baseline KPIs | `backups/2026-08-17-baseline/BARAQ_V1_BASELINE.txt`, `baseline_kpis.json` |
| v1 problem corpus | `tests/regression/v1-known-problems/` |
