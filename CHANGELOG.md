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

## [3.0.0] - 2026-08-31 — "Documentation & ML Strategy"

### Changed
- README rewritten — concise (743→180 lines), points to documentation for details
- ML strategy document rewritten to v3.0 (ensemble stacking, 120K+ dataset, drift detection, cross-stream Markov)
- All 11 documentation files updated to v3.0 (100 rules, 9 TI providers, SOAR actions, data export, ML-enhanced)
- Removed all "Apple" references from documentation and comments

---

## [2.5.0] - 2026-08-30 — "Dataset & Evaluation"

### Added
- **Dataset adapter framework**: OTRF SecurityDatasets, BOTSv1, BOTES adapters (`backend/ml/dataset_adapters/`)
- **BARAQ Dataset 100K builder**: 20 enterprise PCs, 9 department subnets, 28 users, 6 attack scenarios
- **Dataset import service**: REST API endpoint for downloading and importing external datasets
- **Full-DB evaluation module**: `POST /api/evaluation/full-db` for production accuracy metrics
- **Full-DB evaluation UI**: metrics dashboard in the Evaluation page
- **Bulk O(N) training**: pre-computed temporal features for faster ML training
- **Verdict rebalancing script**: attack/benign label correction for honest ML evaluation
- **ML debugging tools**: feature extraction, training status, event analysis scripts

### Fixed
- ML Detection page: clickable stat cards, training status fixes, 'Last Trained: Never' key mismatch
- Network Analyzer: 6 critical gaps (crash, topology risk, edge dedup) + 8 high-priority UX fixes
- CI: resolve all lint failures — black, ruff, flake8, mypy, bandit

---

## [2.4.0] - 2026-08-29 — "Frontend Redesign"

### Added
- **Design token system**: Deep Teal + Gold theme with CSS custom properties
- **20+ glass UI components**: Card, Badge, Button, Tabs, SearchInput, FilterBar, Drawer, Tooltip, SkeletonTable, etc.
- **New pages**: ML Detection, MITRE ATT&CK, Detection Rules, Network Analyzer, Threat Intelligence, Data Export
- **Network Analyzer enhancements**: geolocation enrichment, concentric topology layout, byte analytics (sent/recv), IP investigation view

### Changed
- All frontend pages redesigned with premium glass aesthetic
- Command Center enhanced with live entity-graph stats and AI briefing
- App shell redesigned with new routing and Login page

---

## [2.3.0] - 2026-08-28 — "ML v5/v6 Feature Engineering"

### Added
- **Ensemble stacking meta-learner**: logistic regression combining IF + supervised + Markov predictions (`backend/ml/ensemble.py`)
- **Cross-stream Markov chain**: 4 attack sequence patterns spanning login→process→network (`backend/ml/cross_stream.py`)
- **Adversarial robustness testing**: `backend/ml/robustness.py`
- **Enhanced drift detection**: feature-level PSI + concept drift (`backend/ml/drift.py`)
- **ML model monitoring**: `backend/ml/monitoring.py`
- **Online learning**: incremental model updates (`backend/ml/online.py`)
- **Phase 2 temporal/contextual features**: v6 feature space for ML training
- **Configurable ML validation mode**: bootstrap policy control
- **Cross-platform encrypted vault**: Fernet AES-256-GCM for non-Windows
- **Sysmon availability check**: startup capability banner

### Changed
- Port scan detection window widened and wired through rules engine
- `datetime.utcnow()` deprecated across incident modules

---

## [2.2.0] - 2026-08-25 — "False Positive Hardening"

### Added
- **Trusted-agent FP filter**: `backend/detection/fp_filters.py` allowlist module
- **Regression suite**: PowerShell FP wave fixes pinned per layer

### Changed
- `hidden_execution` rule requires real hidden window (`-WindowStyle Hidden`)
- D003 detector drops bare `-nop` signal, skips trusted agent activity
- Sigma engine FP-suppresses matches referencing trusted agent paths
- Encoded-command sigma rule removes over-broad `-e` substring match

### Fixed
- Alerting dedup: case-insensitive user extraction, unknown-user merge
- Risk ranking: neutral recency for missing `last_seen`
- Alerts API rejects invalid severity filters with 422
- Incident SLA: naive TIMESTAMP columns repaired to TIMESTAMPTZ

---

## [2.1.0] - 2026-08-24 — "Platform Foundation"

### Added
- **PostgreSQL persistence layer**: SQLAlchemy models, session engine, additive migrations
- **Windows telemetry collectors**: event log, Sysmon, PowerShell, network, USB, email
- **Event normalization**: numeric risk scoring + contextual reputation engine
- **Hybrid detection stack**: 100 native MITRE-mapped rules, Sigma engine, 11 YAML correlation chains
- **ML anomaly engine**: Isolation Forest + calibrated supervised models, day-1 bootstrap, drift monitoring
- **Hybrid risk fusion**: entity risk engine, graph analytics, threat-intel enrichment
- **Incident management**: behavior aggregation, correlation findings, SOAR automation
- **FastAPI service layer**: RBAC auth, TOTP/LDAP/OIDC, audit chain, reporting, scheduler
- **Analyst console**: dashboard, alert triage, telemetry, investigation, AI assistant
- **Environment-driven configuration**: encrypted secrets handling
- **Documentation**: user guide, architecture notes, search-language reference, screenshots
- **CI/CD**: regression suites, packaging, operational tooling

---

## [2.0.0] - 2026-08-17 — "Incident Management"

### Added
- **Incident Management**: 8 eligibility policies, deterministic SHA256 fingerprint, lifecycle, suppression, SLA
- **Correlation & RBA**: 9 correlation rules, 10 edge relationship types, entity risk scoring
- **Behavioral Aggregation**: deterministic grouping, sliding windows, membership scoring

---

## [1.5.0] - 2026-08-16 — "Alert & Detection Engine"

### Added
- **Alert Management**: deterministic fingerprint, eligibility policies, dedup windows, lifecycle, suppression
- **Detection Engine**: 5 deterministic versioned detectors (D001–D005), per-field evidence

---

## [1.4.0] - 2026-08-15 — "Platform Hardening"

### Added
- **CI/CD**: Dockerfile, compose.yml, GHCR image, Kubernetes blue-green
- **Observability**: SLO gauges, OpenTelemetry, Grafana dashboard
- **API hardening**: security headers, rate limiting, IP ACLs
- **Scheduled reports + email**: SMTP delivery, schedule CRUD
- **Ticketing integrations**: Jira REST v2 + ServiceNow

---

## [1.3.0] - 2026-08-14 — "Search, Risk & Intelligence"

### Added
- **Search-parity phase**: pipe-based search engine, saved searches + dashboards
- **SOAR automation playbooks**: trigger conditions → ordered actions
- **Entity risk (RBA)**: live tuning, MITRE-weighted contributions
- **Threat-intel feeds**: STIX 2.1, TAXII 2.1, MISP, IOC cache
- **Agent fleet management**: health/stale tracking, fleet overview
- **Data-quality auto-fix**: validation layer, corruption tracking, auto-repair

---

## [1.2.0] - 2026-08-13 — "Detection & Investigation Core"

### Added
- **Alerting roadmap**: severity/risk consistency, context engine, FP analysis, analyst verdicts
- **Investigation engine**: process trees, related-alert clustering, verdict generation, correlated timeline
- **Full-history ML training**: uses ALL collected events
- **MITRE detections library**: 7 new correlation chains + 6 new Sigma rules

---

## [1.1.0] - 2026-08-11 — "BARAQ Naming Alignment"

### Changed
- Environment variables, agent keys, scripts, and documentation unified under BARAQ name

---

## [1.0.0] - 2026-08-05 — "PostgreSQL-First"

### Changed
- PostgreSQL-only migration; SQLite fallback removed

---

## [0.1.0] - 2026-07-30 — "Initial Release"

### Added
- Initial release: agent-based endpoint telemetry, hybrid rule-based + ML detection engine, MITRE ATT&CK mapping, hybrid risk scoring, SOC dashboard, multi-tenant support, evaluation framework
