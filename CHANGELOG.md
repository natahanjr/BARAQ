# Changelog

All notable changes to BARAQ are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.12.0] - 2026-08-17 — "Incident Management"

### Added
- **Incident Management**: 8 eligibility policies (I001 multi-stage, I002 high-risk+activity, I003 repeated high severity, I004 lateral movement, I005 credential abuse, I006 ransomware [T1486/T1490→critical], I007 persistence, I008 analyst escalation), deterministic SHA256 fingerprint (no timestamps/random IDs), `IncidentV2Evidence` rows for groups/findings/alerts/risks, explicit lifecycle (NEW→ACK→INVESTIGATING→CONTAINED→RESOLVED→CLOSED), suppression with 90-day max, SLA priority mapping (critical→P1), `/api/incidents-v2/*` endpoints with CRUD + metrics + graph + timeline
- **Evaluation corpora**: 20 deterministic incident scenarios (INC-001..INC-020)
- **Regression suites**: `tests/regression/v7-known-problems/` (16 tests)

### Fixed
- Policy evaluator signature mismatch: 4 policies accepted only `(groups, findings)` but evaluator passes `(groups, findings, risk)` → added `risk: dict | None` parameter
- I001 multi-stage policy too strict: required `len(groups) >= 2` → relaxed to `len(groups) >= 1`
- Ransomware severity inflation: T1486/T1490 returned `high` instead of `critical` → added override
- Evidence rows never created: `create_incident` wrote zero `IncidentV2Evidence` rows → added `add_evidence` calls
- Evaluation scenarios missing `policy_id`: 11 of 20 scenarios defaulted to ineligible I001 → added explicit `policy_id`
- `transition_incident()` unexpected `now` kwarg → removed from evaluation call
- `suppress_incident()` unexpected `actor` kwarg → changed to `created_by=`
- Evaluation runner `UnboundLocalError`: `passed = 0` inside `try` block → moved before loop
- Evaluation swallowed failures silently: restored `except AssertionError: raise`
- Duplicate incident counting: `repeat`/`concurrent`/`suppress_after` returned 3/4/2 → changed to `len(set(created_ids))`
- Regression tests defaulted to I001 → added `policy_id` to all regression calls
- Suppression `expires_at` naive vs aware datetime crash → passed `EVAL_T0 + timedelta(days=30)` and added `.replace(tzinfo=timezone.utc)` in assertion

## [0.11.0] - 2026-08-17 — "Correlation & Risk"

### Added
- **Correlation & RBA**: Consumes behavior groups only, 9 correlation rules (R001–R009: LATERAL_MOVEMENT, SAME_USER, SAME_SOURCE, DESTINATION_RELATION, TEMPORAL_PROXIMITY, SAME_FAMILY, USER_CHAIN, SOURCE_CHAIN, HOST_CHAIN), 10 edge relationship types with strength weights, relationship-count confidence (bounded 0–1, never summed from group confidences), severity never escalated, pattern-language titles with banned-phrase hard-fail, NEW→ACTIVE→QUIET→CLOSED lifecycle with no silent reopen, partial unique index + ON CONFLICT for concurrency safety
- **Risk Intelligence Engine**: Entity risk scoring (user/host/IP), MITRE-weighted contributions, evidence-age-based decay (24h half-life), peak score never decreases, factor registry (severity, technique, repetition, decay), concurrency-safe `next_risk_id` using `entity_risk_v2_id_seq`, snapshots + audit trail, metrics (distribution, concentration, latency percentiles), evaluation with raw counts
- **Evaluation corpora**: 25 correlation scenarios (CORR-001..025), 10 risk scenarios
- **Regression suites**: `tests/regression/v5-known-problems/`, `tests/regression/v6-known-problems/`

## [0.10.0] - 2026-08-17 — "Behavioral Aggregation"

### Added
- **Behavioral Aggregation**: Consumes v2 alerts only (no raw events), deterministic grouping by (host, user, source, family) with SHA256 fingerprint, behavior families (auth/exec/encryption), sliding windows (auth=15min, exec=30min, encryption=10min), ACTIVE→QUIET→CLOSED lifecycle with no reopening, membership scoring (host .40 + user .25 + source .20 + time .15), flood compression (30 alerts→1 group), suppressed alerts skipped, `behavior_group_evidence` per member
- **Evaluation corpora**: 6 aggregation scenarios (e1..e6)
- **Regression suites**: `tests/regression/v4-known-problems/` (GROUP-001..015)

### Fixed
- `test_suppressed_alerts_never_aggregated` failed: `make_alerts` used `datetime.now()` for suppression check → defaulted `make_alerts` to `now=GROUP_T0` in `tests/aggregation/helpers.py`

## [0.9.0] - 2026-08-16 — "Alert Management"

### Added
- **Alert Management**: Dedicated `ALERT` contract with deterministic fingerprint, detector-aware eligibility policies (ALERT-POLICY-000..005), per-detector dedup windows (D001=15min, D002=15min, D003=10min, D004=10min, D005=5min), explicit lifecycle (OPEN→ACKNOWLEDGED→IN_PROGRESS→RESOLVED→CLOSED/SUPPRESSED), auditable suppression (scope + wildcards + CIDR + 90-day max), analyst workflow (assignment, acknowledgement, 6 feedback types), `alert_audit_events` on every transition, `/api/alerts-v2/*` endpoints
- **Regression suites**: `tests/regression/test_phase3_alerting.py` (ALERT-001..012 + success criteria)

## [0.8.0] - 2026-08-16 — "Detection Engine"

### Added
- **Detection Engine**: 5 deterministic versioned detectors (D001 External RDP, D002 Brute Force, D003 Suspicious PowerShell, D004 Python from Writable Path, D005 Ransomware Behavior), pure `run_detection`/`run_detections` (zero writes), `persist` writes only `detections` with idempotent upsert by campaign key, per-field evidence with `to_explain()`, evaluation benchmark (SC-001..SC-008: TP=5, TN=3, FP=0, FN=0, precision=recall=f1=1.0, fpr=0.0)
- **Regression suites**: `tests/regression/test_phase2_detection.py`

## [0.7.0] - 2026-08-15 — "Platform Hardening"

### Added
- **CI/CD**: multi-stage `Dockerfile`, `compose.yml` API service, GHCR image job + `pip_audit` dependency scan in CI, Kubernetes blue-green manifests and `scripts/blue_green_switch.ps1`
- **Observability**: SLO gauges (`baraq_slo_health`, `baraq_slo_target` via `BARAQ_SLO_DEFINITIONS`), lazy OpenTelemetry OTLP/HTTP export (`BARAQ_OTEL_ENDPOINT`), Grafana dashboard `deploy/grafana/dashboards/baraq-slos.json`
- **API hardening**: security headers + HSTS middleware, per-IP rate limiting with `Retry-After`, optional IP whitelist/blocklist ACLs, configurable request-size cap
- **Frontend UX**: per-row quick triage and bulk triage bar on the Alerts page, notification center, theme tri-state dark/light/system, keyboard shortcuts, color-independent severity markers
- **Scheduled reports + email**: `ReportSchedule` model, `backend/reports/schedule.py` with due logic and SMTP delivery, report schedule CRUD + run-now endpoints, hourly scheduler cycle
- **Ticketing integrations**: Jira REST v2 + ServiceNow table API dispatch, alert `ticket_links`, Python SDK `backend/integrations/sdk.py`
- `.env.example` reference (147 flags) with generator script

## [0.6.0] - 2026-08-15 — "Dataset & Demo"

### Added
- **Dataset Collector**: continuously collects normalized telemetry into `DatasetEvent` records with deterministic SHA-256 fingerprints, automatic CSV export every 24 h, configurable 1,000,000-event target, pause/resume/start, manual export, optional host/user pseudonymization and alert-verdict labels, admin-only downloads with `X-SHA256` checksum header
- **Demo data seeder** (`scripts/seed_demo.py`): 20 curated ATT&CK attack timelines + benign baseline through the real detection pipeline
- **Search-language reference** (`docs/search_language.md`)
- **Production/demo data separation** (`baraq-demo-mode`): events, alerts, entity-risk state, incidents carry a `demo` flag; production views exclude demo data unless `include_demo=1`; session-level partition hook scopes scheduler cycle, RBA and entity-risk escalation

## [0.5.0] - 2026-08-14 — Search, Risk & Intelligence

### Added
- **Search-parity phase**: pipe-based search engine (`backend/search/`, `stats/top/rare/table/fields/sort/where/limit/timechart/transaction` pipes over events and alerts), saved searches + dashboards (`backend/api/saved.py`), SOAR automation playbooks (`backend/automation/`), entity risk (RBA) with live tuning (`backend/risk/entity_risk.py`, `/api/rba/tuning`), multi-source correlation (alert stages + raw-event stages)
- **Online learning (roadmap 4.1)**: PSI concept-drift detection with model health report (`/api/system/ml/drift`), analyst feedback that dampens or boosts alert confidence, model versioning with history
- **Threat-intel feeds (roadmap 4.3)**: `backend/intel/feeds.py` ingests STIX 2.1 bundles, TAXII 2.1 collections, MISP restSearch and plain/CSV lists into an IOC cache (`/api/intel/feeds`, `/api/intel/match`), confidence never downgraded, scheduled refresh every ~3 h
- **Agent fleet management (roadmap 3.4)**: health/stale tracking, agent tags, fleet overview endpoint
- **Data-quality auto-fix**: validation layer (`backend/collectors/validation.py`) discards corrupted rendering-debris events before detection, per-channel corruption tracking with sliding window + persisted snapshots, auto-repair sequence (clear logs, restart EventLog service, retrain ML, notify) with CRITICAL-threshold auto-trigger, `/api/system/data-quality*` endpoints, `data_quality` block on `/api/health`, ML training/scoring skips corrupted history, and a Data Quality card in the dashboard

### Changed
- Notification delivery is now reliable: background worker queue with exponential-backoff retries (`BARAQ_NOTIFY_RETRIES`), JSON file fallback for undeliverable alerts (`BARAQ_NOTIFY_FALLBACK_DIR`), and per-channel health on `/api/system/notifications/health`
- Collector health: `/api/system/collectors/health` reports per-channel statistics and live permission probes; unreadable channels are flagged with an actionable fix hint at startup
- `scripts/elevate_permissions.ps1` (`check`/`grant`) adds the service user to the "Event Log Readers" group and enables the watched channels
- Transient event-log read errors are retried with exponential backoff; persistent privilege errors are surfaced immediately, not retried

## [0.4.0] - 2026-08-13 — Detection & Investigation Core

### Added
- **Alerting roadmap (P0/P1/P2)**: severity/risk consistency (escalation recomputes risk, entity scores capped at 100), context engine (`backend/context/engine.py` - process reputation, dev workflow, localhost/project paths, parent/child, user, command line; demotes dev-sensitive rules under strong dev context and dampens hybrid risk), false-positive analysis (`/api/alerts/fp-analysis`), repeated-detection grouping (`/api/alerts/groups`), analyst verdicts + scoped suppression (`AlertVerdict`/`SuppressionRule`, `/api/alerts/{id}/verdict`, `/api/alerts/suppressions/*`), auto-incident creation for correlation/entity-risk alerts, real per-alert latency measurement in the evaluation suite
- **Investigation engine ("one click, full story")**: the investigation view now reconstructs the whole incident instead of dumping raw events - process trees with root-process identification from Windows 4688 lineage (root -> trigger -> aftermath chains, name-based fallback for gaps, completeness score), related-alert clustering (shared events / correlation chain / host / user / time proximity), automatic verdict generation (context engine, ML agreement, entity risk, analyst feedback weights, verdict history), story-level confidence scoring, a host/user-scoped correlated timeline (evidence, process activity, network, related-alert markers) and context-adjusted risk display (`backend/investigation/`, `GET /api/investigation/alert/{id}`)
- **Full-history ML training**: model training now uses ALL collected events/connections instead of a sample window (`hours=None` = every event; scheduler initial/stale/drift/incremental retrains and the `/api/system/ml/train` endpoint all default to full history)
- **SOC-usability hardening**: benign activity no longer becomes incidents - RBA clusters only count significant alerts (risk >= 25, >= 2 alerts, multi-tactic or high/critical severity; demo telemetry, entity-risk notables and developer-workflow context excluded), auto-incidents only from correlation chains and CRITICAL entity-risk escalations, developer-context evidence dampens entity-risk contributions by 75%
- **MITRE detections library**: 7 new declarative correlation chains (initial-access→execution, persistence→credential access, discovery→lateral movement, collection→exfiltration, defense evasion→impact, download→C2 beacon, event-telemetry credential exploit) and 6 new Sigma rules (curl/wget temp download, IEX DownloadString, NTDS.dit access, vssadmin shadow deletion, recovery mode disable, remote-access tool install)

### Changed
- **Correlation chains**: one alert can never satisfy two chain stages, and alert-stage chains complete within the same detection pass (two-phase detection: base findings are persisted before the correlation engine evaluates, so idle cycles refresh instead of re-firing); every chain alert carries a deterministic `CORR-YYYYMMDD-NNNN` correlation id
- **Entity-risk (RBA) trustworthiness**: risk contributions apply exactly once per alert (idempotent across refreshes/backfills), escalation raises one notable per entity per risk-level change (same-level climbs refresh the open notable; closed notables are reopened instead of duplicated), and escalation evidence/`mitre_id` are derived from the real contributing detections (no hardcoded technique)
- Sigma rules that inspect process fields (Image/CommandLine/NewProcessName) are skipped when the source event data is incomplete, and matching rules are demoted one severity step with a data-integrity note

## [0.3.0] - 2026-08-11 — BARAQ Naming Alignment

### Changed
- Environment variables, agent keys, scripts, and documentation unified under the BARAQ name

## [0.2.0] - 2026-08-05 — PostgreSQL-First Migration

### Changed
- PostgreSQL-only migration; SQLite fallback removed
## [0.1.0] - 2026-07-30 — Initial Release

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML
  detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard,
  multi-tenant support, evaluation framework
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