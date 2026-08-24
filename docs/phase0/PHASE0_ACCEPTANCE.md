# BARAQ Phase 0 — Acceptance Checklist

Status as of 2026-08-17 (baseline tag `baseline-v1-2026-08-17`).

## Repository

- [x] Current BARAQ code tagged as frozen v1 → `baseline-v1-2026-08-17` (commit 69b0259)
- [x] Reproducible commit recorded → `git show baseline-v1-2026-08-17`
- [x] v2 development branch created → `development/v2` (from the tag); `legacy/v1` branch also created
- [x] No new detection rules / threshold tuning / alert or incident changes on v1 (frozen)

## Data

- [x] Complete database backup → `backups/2026-08-17-baseline/database/sentinel.dump` (pg_dump -F c, 977 KB)
- [x] Raw telemetry exported → `telemetry/events.csv` (120 events)
- [x] Alerts exported → `alerts/alerts.csv` (68), `verdicts.csv`
- [x] Incidents exported → `incidents/incidents.csv` (11), links, comments
- [x] Detection records exported → `detections/detections.csv` (266 alert-event links)
- [x] Risk history exported → `risk/` (entity_risk, risk_events, graph)
- [x] ML metadata/models exported → `ml/` (model.bundle.joblib, model_meta.json, dataset_events 1474, audit 301)
- [x] Evaluation history exported → `evaluation/evaluation_runs.csv` (35 runs)
- [x] Rules snapshot → `rules/` (2,518 sigma + 45 correlation/python rule files)

## Baseline

- [x] Current dashboard metrics recorded → `BARAQ_V1_BASELINE.txt` + `baseline_kpis.json`
- [x] Alert/incident ratios calculated → alerts/events 0.567, incidents/alerts 0.162
- [x] Current ML anomaly rate calculated → ml.anomalies_per_event (0 in snapshot; 27 anomalies on harness day)
- [x] Current duplicate rate measured → 47 duplicate alerts across 3 groups
- [x] Current incident duplication documented → INCIDENT_DUPLICATION_001 (playbook opened 2 incidents/alert)
- [x] Known false-positive examples captured → tests/regression/v1-known-problems/ (6 files)

## Architecture

- [x] Event defined → SOC_CONTRACT.md (`EVENT`)
- [x] Finding defined → SOC_CONTRACT.md (`FINDING`)
- [x] Detection defined → SOC_CONTRACT.md (`DETECTION`)
- [x] Alert defined → SOC_CONTRACT.md (`ALERT`, 1:1 with detection)
- [x] Incident defined → SOC_CONTRACT.md (`INCIDENT`, idempotent)
- [x] Risk defined → SOC_CONTRACT.md (`RISK`, single scoring function)
- [x] Response defined → SOC_CONTRACT.md (`RESPONSE`, gated)
- [x] v2 boundary folders established → backend/telemetry|detection|correlation|risk|incidents|ml|response + README contracts

## Safety

- [x] Automatic destructive SOAR actions disabled → `SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0` (default), executor returns SIMULATED
- [x] v2 isolated from production data → ENVIRONMENTS.md (scratch/test DBs, prod read-only for v2)
- [x] Test dataset environment created → baraq_test + backups/ CSVs + regression corpus

## Phase 0 gate

Phase 1 (telemetry) must not start until every box above is checked and the
server is restarted from the `development/v2` branch code.
