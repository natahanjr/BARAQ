# BARAQ Scripts

This directory contains utility scripts for BARAQ administration, development, and data management.

## Production operations (2026-09)

| Script | Purpose |
|---|---|
| `preflight.py` | **Run this before every cutover.** 17 checks (production profile, encryption, SOAR, auth, TLS + health, unauthenticated surface, backup freshness); exits non-zero on any hard failure |
| `db_backup.py` | backup / list / verify / restore. Locates `pg_dump` itself — no `BARAQ_PG_BIN` needed. `--encrypt` for at-rest confidentiality |
| `install_backup_task.ps1` | Registers the daily encrypted backup task (default 03:00). Verify with `(Get-ScheduledTaskInfo -TaskName 'BARAQ-DB-Backup').LastTaskResult` |
| `preflight.py`, `show_paging_routes.py` | Inspect which severities reach email/webhook/Telegram |
| `seed_playbooks.py` | Idempotent starter SOAR playbooks. Safe ones by default; `--with-soar` adds containment playbooks which ship **disabled** |
| `verify_paging.py` | Triggers a real critical alert and proves it reaches a configured webhook |
| `verify_paging_channels.py` | Proves the email (SMTP) and Telegram senders work, offline, against local stubs |
| `webhook_sink.py` | Local webhook receiver used as a stand-in for Slack/Teams while testing. **Test only** |
| `rotate_secrets.py` | Rotates admin password, API keys, session secret |
| `migrate_db.py` | Runs `alembic upgrade head` |

## Agents

| Script | Purpose |
|---|---|
| `agent.ps1` | The default self-contained Windows agent: process + TCP telemetry, no Python required. `-TlsCert` pins the server certificate |
| `install_agent.ps1` | Installs the agent + scheduled task. **Verifies the agent actually reports** before reporting success; defaults to the PowerShell agent, `-AgentType python` for the full one |
| `agent.py` | Full agent (event logs, Sysmon, DNS, USB, registry). Requires the `backend` package + pywin32 deployed, otherwise it cannot collect |
| `agent_updater.ps1` | Hash-verified update with rollback |
| `provision_agent.py` / `provision_fleet.py` | Register agents and issue per-host keys |
| `gen_cert.ps1` | Self-signed SAN certificate → `certs/baraq.crt` + `certs/baraq.key` |
| `import_cert.ps1` | Install that certificate as a trusted root on an endpoint |

## Import Scripts

### train_full.py
Full ML model training on all available data.
```bash
python scripts/train_full.py
```

### train_fast.py
Quick training with reduced sample size for testing.
```bash
python scripts/train_fast.py
```

### train_manual.py
Manual training trigger with custom parameters.
```bash
python scripts/train_manual.py --hours 24
```

### train_capped.py
Training with capped event count for resource-constrained environments.
```bash
python scripts/train_capped.py --max-events 50000
```

### train_direct.py
Direct training bypassing the API layer.
```bash
python scripts/train_direct.py
```

### train_full_bulk.py
Bulk training using pre-computed features.
```bash
python scripts/train_full_bulk.py
```

### trigger_training.py
Trigger training via the API.
```bash
python scripts/trigger_training.py
```

## Dataset Scripts

### sweep_dataset.py
Scan and catalog available datasets.
```bash
python scripts/sweep_dataset.py --data-dir datasets/
```

### validate_realworld.py
Validate detection against real-world telemetry.
```bash
python scripts/validate_realworld.py
```

### tune_parameters.py
Automated parameter tuning for detection rules.
```bash
python scripts/tune_parameters.py
```

## Build Scripts

### start_dev.py
Start development server with auto-reload.
```bash
python scripts/start_dev.py
```

## Database Scripts

### _verify_pg.py
Verify PostgreSQL connection and configuration.
```bash
python scripts/_verify_pg.py
```

### test_full_db_eval.py
Full database evaluation for accuracy metrics.
```bash
python scripts/test_full_db_eval.py
```

### time_features.py
Profile feature extraction timing.
```bash
python scripts/time_features.py
```

## Development Scripts

### build_bootstrap_model.py
Build the bootstrap ML model for day-1 detection.
```bash
python scripts/build_bootstrap_model.py
```

### backfill_fp_demotion.py
Backfill false positive demotion for existing alerts.
```bash
python scripts/backfill_fp_demotion.py
```

### load_test_agents.py
Load testing for agent ingest endpoints.
```bash
python scripts/load_test_agents.py --count 100
```

### perf_benchmark.py
Performance benchmarking suite.
```bash
python scripts/perf_benchmark.py
```

### generate_network_attacks.py
Generate synthetic network attack data for testing.
```bash
python scripts/generate_network_attacks.py
```
