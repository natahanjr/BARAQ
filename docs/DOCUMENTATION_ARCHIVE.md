# BARAQ — Documentation Archive

Consolidated from 25 individual docs. Organized by status.

---

## Completed

| Document | Summary |
|----------|---------|
| **GDPR Processing** | GDPR/CCPA compliance: data controller/processor roles, personal data categories, legal bases, 30-day retention, RBAC, TLS, AES-256-GCM, DSAR/erasure support |
| **TLS Production** | Enforcing HTTPS: certificate provisioning, `BARAQ_TLS=1` startup gate, Secure cookies, verification checklist |
| **Agent Fleet** | Remote telemetry collection: provisioning (`provision_agent.py`), key management, command channel (block/kill/quarantine), health tracking, auto-update |
| **Backup Restore** | PostgreSQL backup/restore via `scripts/db_backup.py`, cryptographic verification, automated daily backups, secrets vault handling |
| **Data Quality** | Auto-fix for corrupted Windows event data, repair sequences (clear logs, restart EventLog, retrain ML), configurable thresholds |
| **Integrations** | Ticketing: Jira, ServiceNow dispatch for high-severity alerts, health tracking, manual dispatch API, SDK |
| **Migrations** | Alembic schema migrations: baseline revision, stamping for pre-Alembic deployments, deployment checklist |
| **ML Strategy** | 4-layer architecture (IF + supervised + Markov + ensemble), 129K dataset, 99.05% accuracy, drift detection (PSI) |
| **Multinode Ops** | Multi-node deployment: process roles, distributed scheduler lock, read replicas, optional Celery, Kubernetes manifests |
| **Performance** | Benchmarks: 2.7 events/s ingest, 99.05% accuracy hold-out, resource footprint on target hardware |
| **Red Team** | 13 attack scenarios (brute force, PowerShell, persistence, port scan, privesc, lateral movement, exfil, C2, log clearing, LOLBin) — 13/13 detected |
| **Sysmon Guide** | Installation/config for 6 high-value event types (Process Create, Network Connect, Process Access, File Create, Registry, File Delete) |
| **Test Results** | 1,300+ tests passing, 0 failures. Detection rule validation, API validation, evaluation results |
| **Threat Intel** | TAXII, STIX, MISP, CSV feed ingestion, DB-cached indicator store, IOC matching |
| **TLS Options** | Self-signed, reverse proxy with Let's Encrypt, SSH tunnel options with rotation/hardening |
| **Windows Service** | NSSM-based service installation, Task Scheduler fallback, ops, upgrades, verification |
| **Gap Analysis** | ~130 items completed, 53 tests added. 11 TODO items remain for feature enrichment |

---

## Ongoing

| Document | Summary | Remaining Work |
|----------|---------|----------------|
| **GAP Analysis 10/10** | 20 gaps found in 2026-09-04 audit: version mismatches, CI running 3/1,921 tests, missing LICENSE, stale docs | High/medium/low priority items unfixed |
| **What's Broken** | 2 critical runtime bugs (`text` and `MAX_REQUEST_BYTES` undefined), blocked PostgreSQL, 393 mypy errors, 5,773 ruff warnings | Bugs identified but not yet fixed |
| **Limitations & Future** | Scope limitations (single-machine, rule coverage, telemetry dependency), ML limitations (training bias, feature gaps, drift) | Horizontal scaling, online learning, public dataset evaluation remain open |

---

## Open / Planned

| Document | Summary | Next Steps |
|----------|---------|------------|
| **Code Signing** | Authenticode binary signing for Windows (SmartScreen/AV trust). Tooling ready | Requires purchasing an Authenticode certificate (~$200-500/year) |
| **Compliance & Export** | Export control (Wassenaar/EAR), GDPR, encryption regs, EU Cyber Resilience Act | Selling-process checklist items incomplete |
| **Pentest Brief** | External penetration test template: scope, rules of engagement, deliverables, acceptance criteria | Template ready; engagement needed |
| **Support SLA** | Support tiers (Standard, Priority, Critical/24x7), response targets, credits, termination | Template ready; needs to be filled per customer |
| **Product Roadmap** | V0.9-V1.4 completed; V2.0 (Full BARAQ) defined; V2.1-V2.7 planned | Multi-tenancy, threat hunting, compliance, integrations, fleet, ML, SOAR |

---

*Consolidated from 25 individual documentation files on 2026-09-08*
