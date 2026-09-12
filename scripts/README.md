# BARAQ Scripts

This directory contains utility scripts for BARAQ administration, development, and data management.

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
