# BARAQ — Documentation Archive

Consolidated from 25 individual docs. Organized by status.

---

## Completed Work

### Core Platform (Phase 0–7)

| Phase | Name | Key Deliverables | Status |
|-------|------|------------------|--------|
| **Phase 0** | Foundation | SOC contract, environments, metrics registry, baseline snapshot, v1 tag, production DB protection | Done |
| **Phase 1** | Telemetry | EVENT schema v1.1, fingerprint dedup, normalization, ingestion pipeline, v2_events table, API | Done |
| **Phase 2** | Detection | DETECTION contract, 5 detectors (D001-D005), registry, engine, FP filter, 98+ tests | Done |
| **Phase 3** | Alerting | ALERT contract, fingerprint, eligibility, dedup, lifecycle, suppression, feedback, 5 tables, 119+ tests | Done |
| **Phase 4** | Aggregation | Behavior Group contract, fingerprint, grouping, lifecycle, 4 tables, 99+ tests | Done |
| **Phase 5** | Correlation | Correlation contract, 9 types, 9 rules, edges, confidence, 5 tables, 107+ tests | Done |
| **Phase 6** | Entity Risk | Entity Risk contract, 14 factors, calculator, decay, propagation, 5 tables, 27+ scenarios | Done |
| **Phase 7** | Incidents | Incident contract, 8 eligibility policies, 10+ tables, lifecycle, suppression, 20 scenarios | Done |

### Security Hardening

| Item | Description | Status |
|------|-------------|--------|
| **Auth hardening** | Password rotation, session invalidation, refresh token rotation, TOCTOU fix | Done |
| **Input sanitization** | LDAP injection (RFC 4515), LIKE injection, SSRF protection, XSS prevention | Done |
| **Credential management** | Remove hardcoded credentials, DPAPI vault, secrets migration/rotation scripts | Done |
| **Token security** | JWT `iat` validation, token refresh, session expiry | Done |
| **Rate limiting** | Redis-backed rate limiting, login lockout | Done |
| **Path security** | Path traversal prevention in SPA fallback, MITRE ID sanitization | Done |
| **Pydantic validation** | Raw dict request body validation via Pydantic models | Done |
| **Password policies** | `password_changed_at` column, session invalidation on password change | Done |

### Frontend

| Item | Description | Status |
|------|-------------|--------|
| **Design system** | Deep Teal + Gold theme, CSS custom properties, 20+ glass UI components | Done |
| **Dashboard** | Live stats, severity cards, telemetry feed, entity graph, AI briefing | Done |
| **Alerts** | Alert queue, filtering, sorting, detail view, verdict submission | Done |
| **Incidents** | Incident list, create, link alerts, timeline, graph | Done |
| **Investigation** | Process trees, related alerts, attack chain visualization | Done |
| **ML Detection** | Model status, training, features, evaluation, rollback | Done |
| **MITRE ATT&CK** | Technique mapping, coverage view, gap analysis | Done |
| **Network Analyzer** | Geolocation, topology, byte analytics, IP investigation | Done |
| **Threat Intelligence** | Feed management, IOC lookup, reputation | Done |
| **UEBA** | User baselines, anomaly detection, risk scoring | Done |
| **Insider Threat** | Threat scoring, indicators, recommended actions | Done |
| **SOAR Automation** | Playbook CRUD, run history, approval workflow | Done |
| **Correlation Rules** | Rules list, severity display, MITRE mapping | Done |
| **Playbook Editor** | Visual playbook creation, trigger conditions, action selection | Done |
| **Real-time Notifications** | WebSocket hook, toast notifications for alerts/incidents | Done |
| **Command Palette** | Ctrl+K navigation, page search, action shortcuts | Done |
| **Theme Toggle** | Dark/light/system theme cycling | Done |
| **Mobile Responsive** | Sidebar overlay, slide-in navigation, responsive layout | Done |
| **Local QR Code** | Canvas-based QR generator, zero dependencies, secrets never leave browser | Done |

### Testing

| Item | Description | Status |
|------|-------------|--------|
| **Auth E2E** | 17 Playwright tests: login, registration, MFA, SSO, validation | Done |
| **Dashboard E2E** | 10 Playwright tests: stats, severity cards, telemetry | Done |
| **Alerts E2E** | 10 Playwright tests: list, filtering, detail, status changes | Done |
| **Users E2E** | 9 Playwright tests: list, create, approve, delete | Done |
| **Phase tests** | 1,300+ tests across all phases, 0 failures | Done |
| **Regression suite** | v1-known-problems corpus tests | Done |
| **Red team** | 13 attack scenarios, 13/13 detected | Done |

### Documentation

| Item | Description | Status |
|------|-------------|--------|
| **Architecture** | System overview, data flow, schema, API endpoints | Done |
| **Deployment** | Dev, production, Docker, Windows agent guides | Done |
| **User Guide** | Login, alerts, incidents, automation, settings | Done |
| **E2E Testing** | Playwright setup, test writing guide | Done |
| **Documentation Archive** | 25 docs consolidated into single reference | Done |
| **GDPR Processing** | GDPR/CCPA compliance, data controller/processor roles, 30-day retention, DSAR/erasure | Done |
| **TLS Production** | HTTPS enforcement, certificate provisioning, Secure cookies, verification checklist | Done |
| **Agent Fleet** | Remote telemetry collection, provisioning, key management, command channel, health tracking | Done |
| **Backup Restore** | PostgreSQL backup/restore, cryptographic verification, automated daily backups | Done |
| **Data Quality** | Auto-fix for corrupted Windows event data, repair sequences, configurable thresholds | Done |
| **Migrations** | Alembic schema migrations, baseline revision, deployment checklist | Done |
| **ML Strategy** | 4-layer architecture (IF + supervised + Markov + ensemble), 129K dataset, 99.05% accuracy | Done |
| **Multinode Ops** | Multi-node deployment, process roles, distributed scheduler lock, read replicas, Kubernetes | Done |
| **Performance** | Benchmarks: 2.7 events/s ingest, 99.05% accuracy hold-out, resource footprint | Done |
| **TLS Options** | Self-signed, reverse proxy with Let's Encrypt, SSH tunnel options | Done |
| **Limitations & Future** | Scope limitations, ML limitations, phased future-work roadmap | Done |

### Infrastructure

| Item | Description | Status |
|------|-------------|--------|
| **Service management** | `start_services.bat`, `stop_services.bat` for PG/backend | Done |
| **Database retry** | Connection retry with exponential backoff (10 attempts, 2s) | Done |
| **Audit export** | `GET /api/auth/audit/export` for SIEM integration (JSON/CSV) | Done |
| **Secrets vault** | DPAPI encryption, migration script, rotation utility | Done |
| **CI/CD** | GitHub Actions pipeline, lint, test, build | Done |
| **Docker** | Dockerfile, compose, GHCR image, Kubernetes manifests | Done |

### Integrations

| Item | Description | Status |
|------|-------------|--------|
| **Jira** | REST v2 ticket dispatch for high-severity alerts | Done |
| **ServiceNow** | Ticket dispatch for high-severity alerts | Done |
| **TAXII/STIX** | Threat intel feed ingestion | Done |
| **MISP** | Threat intel feed ingestion | Done |
| **Sysmon** | Windows telemetry collection | Done |

---

## Open Work

### Critical

| Item | Description | Priority |
|------|-------------|----------|
| **Runtime bugs** | `text` and `MAX_REQUEST_BYTES` undefined errors | Critical |
| **PostgreSQL service** | Blocked Windows service startup | Critical |

### High

| Item | Description | Priority |
|------|-------------|----------|
| **CI test coverage** | Only 3/1,921 tests running in CI | High |
| **mypy errors** | 393 type errors need fixing | High |
| **ruff warnings** | 5,773 lint warnings need fixing | High |
| **Code signing** | Authenticode certificate needed (~$200-500/year) | High |
| **Compliance & Export** | Export control (Wassenaar/EAR), GDPR, encryption regs, EU Cyber Resilience Act | High |

### Medium

| Item | Description | Priority |
|------|-------------|----------|
| **Horizontal scaling** | Multi-node distributed deployment | Medium |
| **Online learning** | Incremental model updates in production | Medium |
| **Public dataset evaluation** | Benchmark against public security datasets | Medium |
| **Pentest engagement** | External penetration test template ready | Medium |
| **Support SLA** | Template ready, needs customer-specific filling | Medium |

### Low / Planned (V2.0+)

| Item | Description | Version |
|------|-------------|---------|
| **Multi-tenancy** | Organization isolation, per-tenant config | V2.1 |
| **Threat hunting** | Proactive threat search interface | V2.2 |
| **Compliance automation** | Auto-check against SOC2/ISO/NIST | V2.3 |
| **Advanced integrations** | More ticketing, SIEM, SOAR platforms | V2.4 |
| **Fleet expansion** | Cross-platform agents (Linux, macOS) | V2.5 |
| **ML advances** | Federated learning, adversarial robustness | V2.6 |
| **SOAR visual editor** | Drag-and-drop playbook builder | V2.7 |

---

## Documentation Reference

| Document | Location |
|----------|----------|
| Architecture | `docs/architecture.md` |
| Deployment | `docs/deployment.md` |
| User Guide | `docs/user-guide.md` |
| Product Roadmap | `docs/product_roadmap.md` |
| E2E Testing | `frontend/E2E_TESTING.md` |
| Security | `SECURITY.md` |
| Changelog | `CHANGELOG.md` |
| Contributing | `CONTRIBUTING.md` |
| License | External (RazForge) |

---

*Last updated: 2026-09-08*
