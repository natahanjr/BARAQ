# Changelog

All notable changes to BARAQ are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Trusted-agent FP filter**: `backend/detection/fp_filters.py` allowlists local automation paths (`AppData\Local\Temp\opencode\` by default; extend via `BARAQ_FP_ALLOW_PATHS`, semicolon-separated). Wired into the native PowerShell rule, the D003 v2 detector, and the Sigma engine
- Regression suite `tests/test_fp_regression_scrubdocs.py` pinning every layer of the August 2026 PowerShell false-positive wave

### Changed
- `hidden_execution` (native rule + D003) now requires a real hidden window (`-WindowStyle Hidden` / `-w hidden`); bare `-NoProfile` / `-nop` carry no signal
- BARAQ Sigma encoded-command rule no longer matches the over-broad `-e` / `-enc` substrings; flags must be standalone tokens and the agent Temp path is filtered

### Fixed
- Alert dedup never merged repeats: user extraction from evidence was case-sensitive; unknown users (`-`, `?`, empty) now share one anchor per rule
- Reopen-guard's inner-loop `continue` bumped counters but still created a new alert; a guard match now absorbs the finding entirely
- Risk ranking: a missing `last_seen` scores neutral recency (1.0) instead of silently halving new alerts' risk

---

## [0.12.0] - 2026-08-17 — "Incident Management"

### Added
- **Incident Management**: 8 eligibility policies (I001–I008), deterministic SHA256 fingerprint, `IncidentV2Evidence` rows, lifecycle (NEW→ACK→INVESTIGATING→CONTAINED→RESOLVED→CLOSED), suppression with 90-day max, SLA priority mapping, `/api/incidents-v2/*` endpoints
- **Evaluation corpora**: 20 deterministic incident scenarios (INC-001..INC-020)
- **Regression suites**: `tests/regression/v7-known-problems/` (16 tests)

### Fixed
- Policy evaluator signature mismatch, I001 multi-stage too strict, ransomware severity inflation, evidence rows never created, evaluation runner errors

---

## [0.11.0] - 2026-08-17 — "Correlation & Risk"

### Added
- **Correlation & RBA**: 9 correlation rules (R001–R009), 10 edge relationship types, relationship-count confidence, pattern-language titles, NEW→ACTIVE→QUIET→CLOSED lifecycle
- **Risk Intelligence Engine**: Entity risk scoring (user/host/IP), MITRE-weighted contributions, evidence-age decay (24h half-life), factor registry, snapshots + audit trail
- **Evaluation corpora**: 25 correlation scenarios, 10 risk scenarios

---

## [0.10.0] - 2026-08-17 — "Behavioral Aggregation"

### Added
- **Behavioral Aggregation**: Deterministic grouping by (host, user, source, family) with SHA256 fingerprint, behavior families (auth/exec/encryption), sliding windows, membership scoring, flood compression
- **Regression suites**: `tests/regression/v4-known-problems/` (GROUP-001..015)

---

## [0.9.0] - 2026-08-16 — "Alert Management"

### Added
- **Alert Management**: Deterministic fingerprint, detector-aware eligibility policies (ALERT-POLICY-000..005), per-detector dedup windows, explicit lifecycle, auditable suppression, analyst workflow, `alert_audit_events`, `/api/alerts-v2/*` endpoints
- **Regression suites**: `tests/regression/test_phase3_alerting.py`

---

## [0.8.0] - 2026-08-16 — "Detection Engine"

### Added
- **Detection Engine**: 5 deterministic versioned detectors (D001–D005), pure `run_detection`/`run_detections`, per-field evidence with `to_explain()`, evaluation benchmark (precision=recall=f1=1.0)
- **Regression suites**: `tests/regression/test_phase2_detection.py`

---

## [0.7.0] - 2026-08-15 — "Platform Hardening"

### Added
- **CI/CD**: multi-stage `Dockerfile`, `compose.yml`, GHCR image job, `pip_audit`, Kubernetes blue-green manifests
- **Observability**: SLO gauges, OpenTelemetry OTLP/HTTP, Grafana dashboard
- **API hardening**: security headers + HSTS, per-IP rate limiting, IP whitelist/blocklist, request-size cap
- **Frontend UX**: per-row quick triage, bulk triage bar, notification center, theme tri-state, keyboard shortcuts
- **Scheduled reports + email**: `ReportSchedule`, SMTP delivery, schedule CRUD
- **Ticketing integrations**: Jira REST v2 + ServiceNow table API
- `.env.example` reference (147 flags)

---

## [0.6.0] - 2026-08-15 — "Dataset & Demo"

### Added
- **Dataset Collector**: normalized telemetry into `DatasetEvent` records, automatic CSV export, 1,000,000-event target, pause/resume, pseudonymization
- **Demo data seeder** (`scripts/seed_demo.py`): 20 curated ATT&CK attack timelines
- **Search-language reference** (`docs/search_language.md`)
- **Production/demo data separation** (`baraq-demo-mode`)

---

## [0.5.0] - 2026-08-14 — "Search, Risk & Intelligence"

### Added
- **Search-parity phase**: pipe-based search engine, saved searches + dashboards, SOAR automation playbooks, entity risk (RBA) with live tuning, multi-source correlation
- **Online learning**: PSI concept-drift detection, analyst feedback, model versioning
- **Threat-intel feeds**: STIX 2.1, TAXII 2.1, MISP, IOC cache
- **Agent fleet management**: health/stale tracking, agent tags, fleet overview
- **Data-quality auto-fix**: validation layer, corruption tracking, auto-repair sequence

### Changed
- Notification delivery: background worker queue with exponential-backoff retries
- Collector health: per-channel statistics and live permission probes

---

## [0.4.0] - 2026-08-13 — "Detection & Investigation Core"

### Added
- **Alerting roadmap (P0/P1/P2)**: severity/risk consistency, context engine, false-positive analysis, repeated-detection grouping, analyst verdicts + scoped suppression, auto-incident creation
- **Investigation engine**: process trees, related-alert clustering, automatic verdict generation, story-level confidence, correlated timeline
- **Full-history ML training**: uses ALL collected events/connections
- **SOC-usability hardening**: significant-alert-only clustering, developer-context dampening
- **MITRE detections library**: 7 new correlation chains + 6 new Sigma rules

### Changed
- Correlation chains: two-phase detection, deterministic correlation IDs
- Entity-risk: idempotent contributions, escalation evidence from real detections

---

## [0.3.0] - 2026-08-11 — "BARAQ Naming Alignment"

### Changed
- Environment variables, agent keys, scripts, and documentation unified under the BARAQ name

---

## [0.2.0] - 2026-08-05 — "PostgreSQL-First Migration"

### Changed
- PostgreSQL-only migration; SQLite fallback removed

---

## [0.1.0] - 2026-07-30 — "Initial Release"

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard, multi-tenant support, evaluation framework

---

## Development Log (2026-08-24 to 2026-08-31)

### 2026-08-31 — Documentation Overhaul
- **docs**: rewrite README — concise, points to documentation for details (743→180 lines)
- **docs**: rewrite ML strategy to v3.0 (ensemble, 120K+ dataset, drift, cross-stream)
- **docs**: fix README inaccuracies (Python 3.13+, PostgreSQL required, missing frontend pages)
- **docs**: update all 11 documentation files to v3.0 (100 rules, 9 TI, SOAR, data export)
- **docs**: reduce screenshots to 3 key views
- **feat(ui)**: improve README, AI analysis redesign with color-coded section cards, styled SOAR confirmation modal, data export page, network bytes BIGINT fix

### 2026-08-30 — Dataset, Evaluation & Network Polish
- **feat(ml)**: add dataset adapter framework (OTRF SecurityDatasets, BOTSv1, BOTES)
- **feat(ml)**: add BARAQ Dataset 100K builder with 6 attack scenarios, 20 enterprise PCs
- **feat(ml)**: add dataset import service and REST API endpoint
- **feat(ml)**: implement bulk O(N) training with pre-computed temporal features
- **feat(eval)**: add full-database evaluation module, API endpoint, and UI
- **feat(dashboard)**: make System Health card functional with live backend data
- **fix(ml)**: improve ML Detection page with clickable stat cards and training fixes
- **fix(network)**: 6 critical gaps + 8 high-priority UX fixes (sorting, filtering, export)
- **fix(ci)**: resolve all CI lint failures — black, ruff, flake8, mypy, bandit
- **chore**: add pyproject.toml for black and ruff linting

### 2026-08-29 — Frontend Apple Glass Redesign
- **feat(design)**: add design token system with Deep Teal + Gold theme
- **feat(ui)**: add 20+ glass UI components and layout shell
- **feat(app)**: redesign App shell with new routing and Login page
- **feat(dashboard)**: enhance Command Center with Apple glass design
- **feat(ml)**: add ML Detection, MITRE ATT&CK and Detection Rules pages
- **feat(network)**: add Network Analyzer and Threat Intelligence pages
- **feat(ops)**: rewrite operations pages with Apple glass design
- **feat(pages)**: rewrite all remaining pages with Apple glass design
- **feat(network)**: geolocation enrichment, concentric topology layout, byte analytics
- **fix(ml)**: fix 'Last Trained: Never' key name mismatch, keep status polling alive
- **fix(backend)**: fix network_stats multi-column query crash

### 2026-08-28 — ML v5/v6 Feature Engineering
- **feat**: ensemble stacking meta-learner for multi-model fusion (logistic regression)
- **feat**: adversarial robustness testing module
- **feat**: cross-stream Markov chain correlation module (4 attack sequence patterns)
- **feat**: enhanced drift detection with feature-level PSI and concept drift
- **feat**: ML model monitoring module
- **feat**: Phase 2 temporal/contextual feature helpers (v6 feature space)
- **feat**: online learning with incremental model updates
- **feat**: configurable ML validation mode and bootstrap policy
- **feat**: cross-platform encrypted vault with Fernet AES-256-GCM
- **feat**: Sysmon availability check and startup capability banner
- **feat**: real-world validation script
- **fix**: widen port scan detection window, deprecate datetime.utcnow()
- **docs**: document known limitations and their mitigation status

### 2026-08-25 — False Positive Hardening
- **feat**: trusted-agent FP filter module (BARAQ_FP_ALLOW_PATHS allowlist)
- **fix**: powershell rule — hidden_execution requires a real hidden window
- **fix**: D003 detector — drop bare -nop signal, skip trusted agent activity
- **fix**: sigma engine — FP-suppress matches referencing trusted agent paths
- **fix**: baraq encoded-command sigma rule — remove over-broad -e substring match
- **fix**: alerting dedup — case-insensitive user extraction, unknown-user merge
- **fix**: risk ranking — neutral recency for missing last_seen
- **fix**: alerts API rejects invalid severity filters with 422
- **fix**: incident SLA — repair naive TIMESTAMP columns to TIMESTAMPTZ
- **test**: regression suite pinning each layer of the PowerShell FP wave fixes

### 2026-08-24 — Initial Platform Build
- **feat**: PostgreSQL persistence layer — models, session engine, additive migrations
- **feat**: Windows telemetry collectors — event log, Sysmon, PowerShell, network, USB, email
- **feat**: event normalization with numeric risk scoring + contextual reputation engine
- **feat**: hybrid detection stack — 100 native MITRE-mapped rules, Sigma engine, 11 correlation chains
- **feat**: ML anomaly engine — Isolation Forest + calibrated supervised models, day-1 bootstrap, drift monitoring
- **feat**: hybrid risk fusion, entity risk engine, graph analytics, threat-intel enrichment
- **feat**: incident management, behavior aggregation, correlation findings, SOAR automation
- **feat**: FastAPI service layer — RBAC auth, TOTP/LDAP/OIDC, audit chain, reporting, scheduler
- **feat**: analyst console — dashboard, alert triage, telemetry, investigation, AI assistant
- **feat**: environment-driven configuration core with encrypted secrets handling
- **docs**: user guide, architecture notes, search-language reference, screenshots
- **chore**: project scaffolding, license, contribution and security policies
- **test**: regression suites, CI pipelines, packaging and operational tooling
