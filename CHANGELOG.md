# Changelog

All notable changes to BARAQ are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Public open-source release of the BARAQ platform
- `CONTRIBUTING.md` with workflow, commit conventions, and AI-assisted
  contribution policy
- MIT license
- Agent fleet management (roadmap 3.4): health/stale tracking, agent tags,
  fleet overview endpoint
- Online learning (roadmap 4.1): PSI concept-drift detection with model
  health report (`/api/system/ml/drift`), analyst feedback that dampens or
  boosts alert confidence, model versioning with history
- Threat-intel feeds (roadmap 4.3): `backend/intel/feeds.py` ingests
  STIX 2.1 bundles, TAXII 2.1 collections, MISP restSearch and plain/CSV
  lists into an IOC cache (`/api/intel/feeds`, `/api/intel/match`),
  confidence never downgraded, scheduled refresh every ~3 h
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
- Data-quality auto-fix: validation layer (`backend/collectors/validation.py`)
  discards corrupted rendering-debris events before detection (the main
  source of false-positive process alerts), per-channel corruption tracking
  with sliding window + persisted snapshots, auto-repair sequence (clear
  logs, restart EventLog service, retrain ML, notify) with CRITICAL-threshold
  auto-trigger, `/api/system/data-quality*` endpoints, `data_quality` block
  on `/api/health`, ML training/scoring skips corrupted history, and a Data
  Quality card in the dashboard (see `documentation/data_quality.md`)

### Changed
- Sigma rules that inspect process fields (Image/CommandLine/NewProcessName)
  are skipped when the source event data is incomplete, and matching rules
  are demoted one severity step with a data-integrity note (see
  `data_integrity` field on events)
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

## [0.3.0] - 2026-08-11

### Changed
- Environment variables, agent keys, scripts, and documentation aligned to
  the BARAQ name

## [0.2.0] - 2026-08-05

### Changed
- PostgreSQL-only migration; SQLite fallback removed

## [0.1.0] - 2026-07-30

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML
  detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard,
  multi-tenant support, evaluation framework
