# Changelog

All notable changes to BARAQ are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- [placeholder for upcoming work]

## [1.0.0] - 2026-08-16 — "BARAQ Lightning" Release

### Added
- **Dataset Collector (Telemetry → research dataset)**: continuously
  collects normalized telemetry into `DatasetEvent` records with
  deterministic SHA-256 fingerprints (dedup via unique constraints),
  automatic CSV export every 24 h (`events_per_file` hard split boundary
  with `part_00N` numbering, SHA-256 per part, JSON manifest with
  dataset/version metadata), configurable 1,000,000-event target that
  completes the collection session (normal telemetry unaffected),
  pause/resume/start, manual export (background thread, never blocks
  ingestion), optional host/user pseudonymization and alert-verdict
  labels, admin-only downloads with `X-SHA256` checksum header, and a
  Dataset Collector tab in Telemetry (`backend/dataset/`,
  `backend/api/dataset.py`, `GET/POST /api/telemetry/dataset/*`)
- **Demo data seeder** (`scripts/seed_demo.py`): 20 curated ATT&CK attack
  timelines + benign baseline through the real detection pipeline, with
  incidents, playbooks, saved searches and dashboards
- **Search-language reference** (`docs/search_language.md`)
- Public open-source release of the BARAQ platform
- `CONTRIBUTING.md` with workflow, commit conventions, and AI-assisted
  contribution policy
- MIT license
- CI/CD (roadmap 5.1): multi-stage `Dockerfile`, `compose.yml` API service,
  GHCR image job + `pip_audit` dependency scan in CI, Kubernetes
  blue-green manifests and `scripts/blue_green_switch.ps1`
- Observability (roadmap 5.2): SLO gauges (`baraq_slo_health`,
  `baraq_slo_target` via `BARAQ_SLO_DEFINITIONS`), lazy OpenTelemetry
  OTLP/HTTP export (`BARAQ_OTEL_ENDPOINT`), Grafana dashboard
  `deploy/grafana/dashboards/baraq-slos.json`
- API hardening (roadmap 5.3): security headers + HSTS middleware, per-IP
  rate limiting with `Retry-After`, optional IP whitelist/blocklist ACLs,
  configurable request-size cap
- Frontend UX (roadmap 6.1): per-row quick triage and bulk triage bar on
  the Alerts page (investigate / contain / close / fix)
- Scheduled reports + email (roadmap 6.2): `ReportSchedule` model,
  `backend/reports/schedule.py` with due logic and SMTP delivery, report
  schedule CRUD + run-now endpoints, hourly scheduler cycle, fixed Celery
  `baraq.scheduled_report` task
- Ticketing integrations (roadmap 6.3): Jira REST v2 + ServiceNow table
  API dispatch with per-channel health (`backend/integrations/client.py`,
  `/api/integrations/*`), alert `ticket_links`, and the official Python
  SDK `backend/integrations/sdk.py` (`BARAQClient`)
- `.env.example` reference (147 flags) with a generator script
  (`scripts/gen_env_example.py`)

### Changed
- **"BARAQ Lightning" UI overhaul** (`baraq-lightning-ui`): obsidian
  dark theme (`#0A0E17` background, `#131B2A` steel-navy surfaces) with
  an electric-cyan (`#00F0FF`) / neon-violet (`#7B61FF`) palette and
  glass-morphism cards (gradient hairlines + backdrop blur) across every
  page. New lightning logo (bolt through hex shield) on login and shell.
  Sidebar rebuilt as a collapsible "Blade" with four pods (INTEL, ENGAGE,
  ADMIN, AUGMENT), icons-only collapse mode, violet active bar and pulsing
  critical badges; header gains pulsing system-status dot, universal
  search, live UTC/local clock, compact readouts and a War Room toggle.
  Dashboard rebuilt as the War Room with a 5-tile KPI row (score, open
  incidents, events/EPS, threat-intel feed health, critical threats),
  tactical MITRE heatmap and alert queue. New **⚡ Strike** one-click SOAR
  containment (terminal modal + toast) with auto incident creation, a
  global AI Assistant drawer with floating launcher, `Ctrl+K` command
  palette, lightning-streak page transitions and skeleton-loading styles;
  search page rebuilt as a console-style glass terminal with severity
  chips; login, error screen, entity graph, evaluation, RBA and dashboards
  recolored to the palette
- **Elite SOC analyst command center** (frontend): war-room dashboard rebuilt
  around the analyst workflow — 6 KPI cards (Security Score, Open Incidents,
  Active Alerts, High Risk Entities, Events, Threat Intel), incident queue
  with filters, bulk triage (status/severity/assign/close) and SLA-aware age
  column, Active Threats panel (critical/high only, never all-red), expandable
  event-level threat timeline with 30m/1h/6h/24h range, attack trends with
  1h-30d windows, detection performance from the evaluation suite, MITRE
  ATT&CK coverage with actionable "coverage gap → Create Detection" links,
  SOAR response status (runs today, success rate, failed actions), risk
  intelligence with per-entity contributing factors, analyst workload + SLA
  aging, ML intelligence (drift monitor per stream) and platform health;
  secondary panels load independently so no slow endpoint can block the
  command center
- **Analyst ergonomics** (frontend): notification center (actionable events
  only: critical alerts, ML anomalies, default credentials, untrained model),
  theme tri-state dark/light/system following the OS, keyboard shortcuts
  (`g d/a/i/e/m/s/u/r` jumps, `n` incidents, `/` search, `?` help modal),
  color-independent severity markers (● ▲ ◆ ○), reduced glow intensity
- **Production/demo data separation** (`baraq-demo-mode`): events, alerts,
  entity-risk state, incidents and all child telemetry tables carry a `demo`
  flag. Production views and the detection pipeline exclude demo data unless
  the console explicitly requests it (`include_demo=1`). A session-level
  partition hook (soft-delete style, `session.info["baraq_demo"]`) scopes the
  scheduler cycle, RBA and entity-risk escalation so seeded demo telemetry can
  never be re-detected as production alerts or merged into production state;
  `scripts/seed_demo.py` now runs schema migrations before seeding
- **Demo mode toggle** in the console top bar (persisted per browser),
  rebuildable with `npm run build`

## [0.5.0] - 2026-08-14 — Search, Risk & Intelligence

### Added
- **Search-parity phase**: pipe-based search engine (`backend/search/`,
  `stats/top/rare/table/fields/sort/where/limit/timechart/transaction`
  pipes over events and alerts), saved searches + dashboards
  (`backend/api/saved.py`), SOAR automation playbooks
  (`backend/automation/`), entity risk (RBA) with live tuning
  (`backend/risk/entity_risk.py`, `/api/rba/tuning`), multi-source
  correlation (alert stages + raw-event stages)
- **Online learning (roadmap 4.1)**: PSI concept-drift detection with model
  health report (`/api/system/ml/drift`), analyst feedback that dampens or
  boosts alert confidence, model versioning with history
- **Threat-intel feeds (roadmap 4.3)**: `backend/intel/feeds.py` ingests
  STIX 2.1 bundles, TAXII 2.1 collections, MISP restSearch and plain/CSV
  lists into an IOC cache (`/api/intel/feeds`, `/api/intel/match`),
  confidence never downgraded, scheduled refresh every ~3 h
- **Agent fleet management (roadmap 3.4)**: health/stale tracking, agent
  tags, fleet overview endpoint
- **Data-quality auto-fix**: validation layer
  (`backend/collectors/validation.py`) discards corrupted rendering-debris
  events before detection (the main source of false-positive process
  alerts), per-channel corruption tracking with sliding window + persisted
  snapshots, auto-repair sequence (clear logs, restart EventLog service,
  retrain ML, notify) with CRITICAL-threshold auto-trigger,
  `/api/system/data-quality*` endpoints, `data_quality` block on
  `/api/health`, ML training/scoring skips corrupted history, and a Data
  Quality card in the dashboard (see `documentation/data_quality.md`)

### Changed
- Notification delivery is now reliable: background worker queue with
  exponential-backoff retries (`BARAQ_NOTIFY_RETRIES`), JSON file fallback
  for undeliverable alerts (`BARAQ_NOTIFY_FALLBACK_DIR`), and per-channel
  health on `/api/system/notifications/health`
- Collector health: `/api/system/collectors/health` reports per-channel
  statistics and live permission probes; unreadable channels (e.g. the
  Security log without the "Event Log Readers" group - win32 error 1314)
  are flagged with an actionable fix hint at startup
- `scripts/elevate_permissions.ps1` (`check`/`grant`) adds the service user
  to the "Event Log Readers" group and enables the watched channels
- Transient event-log read errors are retried with exponential backoff;
  persistent privilege errors are surfaced immediately, not retried

## [0.4.0] - 2026-08-13 — Detection & Investigation Core

### Added
- **Alerting roadmap (P0/P1/P2)**: severity/risk consistency (escalation
  recomputes risk, entity scores capped at 100), context engine
  (`backend/context/engine.py` - process reputation, dev workflow,
  localhost/project paths, parent/child, user, command line; demotes
  dev-sensitive rules under strong dev context and dampens hybrid risk),
  false-positive analysis (`/api/alerts/fp-analysis`), repeated-detection
  grouping (`/api/alerts/groups`), analyst verdicts + scoped suppression
  (`AlertVerdict`/`SuppressionRule`, `/api/alerts/{id}/verdict`,
  `/api/alerts/suppressions/*`), auto-incident creation for
  correlation/entity-risk alerts, real per-alert latency measurement in
  the evaluation suite (last evidence event to alert creation, avg/p50/
  p95/max)
- **Investigation engine ("one click, full story")**: the investigation
  view now reconstructs the whole incident instead of dumping raw
  events - process trees with root-process identification from Windows
  4688 lineage (root -> trigger -> aftermath chains, name-based fallback
  for gaps, completeness score), related-alert clustering (shared
  events / correlation chain / host / user / time proximity), automatic
  verdict generation (context engine, ML agreement, entity risk,
  analyst feedback weights, verdict history), story-level confidence
  scoring, a host/user-scoped correlated timeline (evidence, process
  activity, network, related-alert markers) and context-adjusted risk
  display (raw vs adjusted score with modifiers and entity risk)
  (`backend/investigation/`, `GET /api/investigation/alert/{id}`)
- **Full-history ML training**: model training now uses ALL collected
  events/connections instead of a sample window (`hours=None` = every
  event; scheduler initial/stale/drift/incremental retrains and the
  `/api/system/ml/train` endpoint all default to full history)
- **SOC-usability hardening**: benign activity no longer becomes
  incidents - RBA clusters only count significant alerts (risk >= 25,
  >= 2 alerts, multi-tactic or high/critical severity; demo telemetry,
  entity-risk notables and developer-workflow context excluded),
  auto-incidents only from correlation chains and CRITICAL entity-risk
  escalations, developer-context evidence dampens entity-risk
  contributions by 75%
- **MITRE detections library**: 7 new declarative correlation chains
  (initial-access→execution, persistence→credential access,
  discovery→lateral movement, collection→exfiltration, defense
  evasion→impact, download→C2 beacon, event-telemetry credential
  exploit) and 6 new Sigma rules (curl/wget temp download, IEX
  DownloadString, NTDS.dit access, vssadmin shadow deletion, recovery
  mode disable, remote-access tool install)

### Changed
- **Correlation chains**: one alert can never satisfy two chain stages, and
  alert-stage chains complete within the same detection pass (two-phase
  detection: base findings are persisted before the correlation engine
  evaluates, so idle cycles refresh instead of re-firing); every chain alert
  carries a deterministic `CORR-YYYYMMDD-NNNN` correlation id
- **Entity-risk (RBA) trustworthiness**: risk contributions apply exactly
  once per alert (idempotent across refreshes/backfills), escalation raises
  one notable per entity per risk-level change (same-level climbs refresh the
  open notable; closed notables are reopened instead of duplicated), and
  escalation evidence/`mitre_id` are derived from the real contributing
  detections (no hardcoded technique)
- Sigma rules that inspect process fields (Image/CommandLine/NewProcessName)
  are skipped when the source event data is incomplete, and matching rules
  are demoted one severity step with a data-integrity note (see
  `data_integrity` field on events)

## [0.3.0] - 2026-08-11 — BARAQ Naming Alignment

### Changed
- Environment variables, agent keys, scripts, and documentation unified
  under the BARAQ name

## [0.2.0] - 2026-08-05 — PostgreSQL-First Migration

### Changed
- PostgreSQL-only migration; SQLite fallback removed

## [0.1.0] - 2026-07-30 — Initial Release

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML
  detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard,
  multi-tenant support, evaluation framework