# BARAQ

### AI-Powered Security Operations Platform & Cybersecurity Research Framework

> Self-hosted Windows endpoint SOC: telemetry collection, hybrid rule + ML detection, MITRE ATT&CK mapping, investigation, SOAR automation, threat intelligence, and AI-assisted analysis — all on a single machine or scaled to agent/server fleets.

[![Python Package](https://github.com/natahanjr/BARAQ/actions/workflows/python-package.yml/badge.svg)](https://github.com/natahanjr/BARAQ/actions/workflows/python-package.yml)
[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React%2018-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## At a Glance

| Capability | BARAQ |
|---|---|
| Deployment | Self-hosted (local or fleet) |
| Endpoint | Windows 10/11 |
| Detection | 100 native rules + 2,512 Sigma rules + 4-layer ML + 11 correlation chains |
| Framework | MITRE ATT&CK (14 tactic groups) |
| Investigation | Alerts + incidents + entity graph + AI analysis with RAG |
| Automation | SOAR playbooks + manual response (block, isolate, kill, quarantine, disable) |
| Intelligence | IOC enrichment from 9 providers (3-tier loop) |
| Research | ML evaluation framework + attack simulation + 254K event dataset |
| API | FastAPI / OpenAPI with RBAC |
| Security | 2FA, RBAC, LDAP/OIDC SSO, encryption at rest, audit chain |

---

## Screenshots

| SOC Dashboard | Security Alerts | Threat Investigation |
|---|---|---|
| ![SOC Dashboard](docs/screenshots/dashboard.png) | ![Security Alerts](docs/screenshots/Security%20Alerts.png) | ![Threat Investigation](docs/screenshots/Threat%20Investigation.png) |

---

## Quick Start

### Requirements

- **Windows 10/11** (target: Windows 11, Intel i5, 8GB+ RAM)
- **Python 3.13+** (tested with 3.13.15)
- **Node.js 18+** — only for building the dashboard
- **PostgreSQL 16+** on `127.0.0.1:5432` (required — no SQLite fallback)

### Launch

```powershell
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
.\start.bat
```

On first run: creates venv, installs deps, builds dashboard, provisions PostgreSQL, generates bootstrap ML model, prints admin credentials (save them), starts backend on `http://127.0.0.1:8001`.

### URLs

| What | URL |
|---|---|
| Dashboard | `http://127.0.0.1:8001` |
| API docs (Swagger) | `http://127.0.0.1:8001/docs` |
| Health check | `http://127.0.0.1:8001/api/health` |

---

## How BARAQ Works

```
Windows Endpoint
       │
       ▼
┌─────────────────────┐
│ Telemetry Collection │  event logs, processes, network, PowerShell, Sysmon
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│   Normalization      │  common schema, risk score 0–100 per event
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│     Detection        │  100 rules + 2,512 Sigma + 11 correlation chains + 4-layer ML
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│   Risk Scoring       │  60% rule + 40% ML → 0–100 + severity level
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Enrichment           │  MITRE ATT&CK + threat intel IOC (9 providers)
└──────────┬──────────┘
           ▼
┌─────────────────────┐
│ Investigation / SOAR │  AI analysis, attack chain, playbooks, response actions
└─────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13+, FastAPI, uvicorn, SQLAlchemy, psycopg3 |
| Frontend | React 18, Tailwind CSS 4, Recharts, WebSocket live updates |
| Database | PostgreSQL 16+ |
| Detection | 100 native rules · SigmaHQ (2,512 rules) · 11 YAML correlation chains |
| ML | Isolation Forest + XGBoost/RandomForest + Cross-Stream Markov + Ensemble Meta-Learner |
| Integration | Kafka · Redis Streams · Elasticsearch · Prometheus + Grafana · LDAP/AD · OIDC |
| Security | RBAC · TOTP 2FA · AES-256-GCM at rest · DPAPI vault · SHA-256 audit chain |

---

## Project Structure

```
BARAQ/
├── backend/
│   ├── ai/            # AI security assistant (local engine + RAG)
│   ├── api/           # FastAPI routers
│   ├── automation/    # SOAR playbooks (auto-fire from pipeline)
│   ├── collectors/    # Windows event log, process, network, PowerShell, Sysmon
│   ├── database/      # SQLAlchemy models + PostgreSQL
│   ├── detection/     # 100 rules, Sigma engine, 11 correlation chains
│   ├── evaluation/    # Detection evaluation framework
│   ├── graph/         # Entity graph (Postgres / Neo4j)
│   ├── ml/            # 4-layer ML: IF + XGB + Markov + Ensemble
│   ├── response/      # SOAR actions (Windows-native)
│   ├── risk/          # Hybrid risk scoring + entity risk (RBA)
│   ├── search/        # Pipe-based search engine
│   ├── streaming/     # Kafka / Redis / ES forwarding
│   ├── threatintel/   # IOC enrichment (9 providers)
│   └── vulnscan/      # CVE matching engine
├── frontend/          # React 18 + Tailwind CSS 4 dashboard
├── scripts/           # Agent, build, cert gen, seed_demo, sigma_pull, tune
├── tests/             # 1,300+ tests
├── documentation/     # Full documentation suite
└── docs/              # Screenshots, search language reference
```

---

## Research

BARAQ is a platform for reproducible cybersecurity experimentation.

- **254K event dataset** — 120K synthetic (60% attack / 40% benign) + 133K from OTRF Security-Datasets
- **4-layer ML** — Isolation Forest + XGBoost + Cross-Stream Markov + Ensemble Meta-Learner
- **Evaluation framework** — isolated DB, accuracy/precision/recall/F1/FPR/detection time
- **Hold-out evaluation** — detection on attacks the ML never trained on (99.05% accuracy, 95.12% recall, 0% FPR)
- **Parameter tuning** — grid-search + Bayesian optimization for rule thresholds
- **Dataset adapters** — BOTSv1, BOTES, OTRF Security-Datasets

```powershell
python scripts\seed_demo.py                            # generate demo data
curl.exe -X POST http://127.0.0.1:8001/api/evaluation/run   # run evaluation
curl.exe -X POST http://127.0.0.1:8001/api/system/ml/train  # train ML
```

---

## Security

- Multi-user RBAC (analyst / admin)
- TOTP 2FA, LDAP/AD + OIDC SSO (Entra ID, Keycloak)
- AES-256-GCM encryption at rest, DPAPI secret vault
- Tamper-evident SHA-256 audit chain
- CSRF protection, request-size guards, login rate limiting
- SOAR actions require UAC elevation

See [`SECURITY.md`](SECURITY.md) for the coordinated disclosure policy.

---

## Running Tests

```powershell
python -m pytest tests -v
```

**1,300+ tests** covering detection rules, API, collectors, pipeline, ML, threat intel, SOAR, data export, auth, evaluation, and more. See [`documentation/test_results.md`](documentation/test_results.md).

---

## Documentation

| Document | Description |
|---|---|
| [`documentation/BARAQ_Combined_Guide.md`](documentation/BARAQ_Combined_Guide.md) | **Start here** — consolidated operator/maintenance walkthrough |
| [`documentation/user_manual.md`](documentation/user_manual.md) | Complete operator guide |
| [`documentation/architecture.md`](documentation/architecture.md) | System architecture and data flow |
| [`documentation/database_schema.md`](documentation/database_schema.md) | Schema, tables, and ER notes |
| [`documentation/ml_strategy_and_validation.md`](documentation/ml_strategy_and_validation.md) | ML training, validation, dataset architecture |
| [`documentation/deployment_guide.md`](documentation/deployment_guide.md) | Central fleet deployment guide |
| [`documentation/test_results.md`](documentation/test_results.md) | Test suite results and coverage |
| [`documentation/red_team_validation.md`](documentation/red_team_validation.md) | Live-attack validation |
| [`documentation/performance_benchmarks.md`](documentation/performance_benchmarks.md) | Throughput, latency, memory benchmarks |
| [`docs/search_language.md`](docs/search_language.md) | Search language reference |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution workflow and conventions |

---

## Known Limitations

| Limitation | Status |
|---|---|
| Poll-based collection (15 s blind spot) | Mitigated — configurable, remote agents push in real time |
| ML trained on synthetic corpus | Mitigated — scheduler retrains on real telemetry |
| Multi-node / HA | Partial — single-writer HA, stateless API replicas |

**Frontend pages not yet implemented** (backend APIs exist): Search (`POST /api/search`), Entity Graph (`GET /api/entities/graph`), Vulnerability Scanning (`POST /api/vulnscan/run`), Sigma Rule Management (`scripts/sigma_pull.py`).

---

## Contributors

- [@natahanjr](https://github.com/natahanjr) — design, architecture, security model, and maintenance

Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
