# BARAQ

AI-Powered Security Operations Platform for Windows endpoints.

> Self-hosted SOC: telemetry collection, hybrid rule + ML detection, MITRE ATT&CK mapping, investigation, SOAR automation, threat intelligence, and AI-assisted analysis.

[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React%2019-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![CI](https://github.com/natahanjr/BARAQ/actions/workflows/python-package.yml/badge.svg)](https://github.com/natahanjr/BARAQ/actions)
[![License](https://img.shields.io/badge/license-RazForge-blue)](LICENSE)

---

## Quick Start

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
docker compose up -d
```

That's it. Backend on `http://localhost:8001`, PostgreSQL and Redis included.

**One-liner install (Linux/macOS):**
```bash
curl -fsSL https://raw.githubusercontent.com/natahanjr/BARAQ/main/install.sh | bash
```

### Option 2: Windows (Native)

**Requirements:** Windows 10/11, Python 3.12+, Node.js 22+, PostgreSQL 16+

```powershell
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
.\start.bat
```

### URLs

| What | URL |
|---|---|
| Dashboard | `http://localhost:8001` |
| API docs (Swagger) | `http://localhost:8001/docs` |
| API docs (ReDoc) | `http://localhost:8001/redoc` |
| Health check | `http://localhost:8001/api/health` |

### Default Credentials

| User | Password | Role |
|---|---|---|
| `admin` | `BaraqAdmin2026!` | Admin |

---

## Docker Compose Services

| Service | Port | Description |
|---|---|---|
| `api` | 8001 | FastAPI backend (API + scheduler) |
| `db` | 5432 | PostgreSQL 16 |
| `redis` | 6379 | Redis 7 (caching, rate limiting) |
| `prometheus` | 9090 | Metrics (opt-in: `--profile monitoring`) |
| `grafana` | 3000 | Dashboards (opt-in: `--profile monitoring`) |

```bash
# Development (API + DB + Redis)
docker compose up -d

# With monitoring (Prometheus + Grafana)
docker compose --profile monitoring up -d

# Production
docker compose --profile production up -d
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, FastAPI, SQLAlchemy, psycopg3 |
| Frontend | React 19, Tailwind CSS 4, Recharts, Vite 8 |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Detection | 100 native rules + 2,512 Sigma rules + 11 correlation chains |
| ML | Isolation Forest + XGBoost + Cross-Stream Markov + Ensemble Meta-Learner |
| Intelligence | IOC enrichment from 9 providers (AbuseIPDB, OTX, VirusTotal, abuse.ch, etc.) |
| Security | RBAC, TOTP 2FA, LDAP/OIDC SSO, AES-256-GCM at rest, SHA-256 audit chain |

---

## Project Structure

```
BARAQ/
├── backend/
│   ├── api/           # FastAPI routers
│   ├── collectors/    # Windows event log, process, network, PowerShell, Sysmon
│   ├── database/      # SQLAlchemy models + PostgreSQL
│   ├── detection/     # 100 rules, Sigma engine, 11 correlation chains
│   ├── ml/            # 4-layer ML: IF + XGB + Markov + Ensemble
│   ├── response/      # SOAR actions (Windows-native)
│   ├── threatintel/   # IOC enrichment (9 providers)
│   └── vulnscan/      # CVE matching engine
├── frontend/          # React 19 dashboard
├── scripts/           # Agent, build, seed_demo, sigma_pull, tune
├── tests/             # 1,300+ tests
├── deploy/            # Docker, Prometheus, Grafana configs
└── docs/              # Full documentation suite
```

---

## Development

```bash
# Clone and setup
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ

# Docker (recommended)
docker compose up -d

# Or native (Windows)
.\start.bat

# Run tests
python -m pytest tests -v

# Lint
ruff check .

# Type check
pyright backend
```

---

## API Documentation

BARAQ auto-generates OpenAPI documentation:

| Format | URL |
|---|---|
| Swagger UI | `http://localhost:8001/docs` |
| ReDoc | `http://localhost:8001/redoc` |
| OpenAPI JSON | `http://localhost:8001/openapi.json` |

---

## Documentation

| Document | Description |
|---|---|
| [`docs/PRODUCTION_DEPLOY.md`](docs/PRODUCTION_DEPLOY.md) | **Production LAN runbook (Windows, 50–200 endpoints, replace Splunk)** |
| [`docs/BARAQ_Combined_Guide.md`](docs/BARAQ_Combined_Guide.md) | Operator/maintenance walkthrough |
| [`docs/user-guide.md`](docs/user-guide.md) | Complete operator guide |
| [`docs/architecture.md`](docs/architecture.md) | System architecture and data flow |
| [`docs/ml_strategy_and_validation.md`](docs/ml_strategy_and_validation.md) | ML training and validation |
| [`docs/deployment.md`](docs/deployment.md) | Fleet deployment guide |
| [`docs/dataset-import.md`](docs/dataset-import.md) | External dataset import guide |
| [`docs/ml-training.md`](docs/ml-training.md) | ML training configuration |

---

## Dataset Statistics

BARAQ supports importing external security datasets for ML training:

| Dataset | Events | Format | Source |
|---|---|---|---|
| OTRF Security-Datasets | 310K+ | JSON/CSV | [OTRF](https://github.com/OTRF/Security-Datasets) |
| BOTSv1 | 1.8M | CSV | [Splunk](https://github.com/splunk/botsv1) |
| BOTES | 2M+ | CSV | [Splunk](https://github.com/splunk/botes) |

---

## ML Performance

| Model | AUC | Recall | Samples |
|---|---|---|---|
| Network (v12) | 0.999 | 99.7% | 310K |
| Process (v10) | 0.865 | 86.5% | 310K |
| Login (v37) | 0.870 | 21.4% | 995 |
| **Full-DB Eval** | **0.999** | **100%** | **310K** |

---

## License

Copyright (c) 2026 [Natahan](https://github.com/natahanjr) — [RazForge Lab](https://github.com/natahanjr)

Licensed under the [RazForge License](https://github.com/RazForge/.github/blob/main/RAZFORGE-SOURCE-AVAILABLE-LICENSE.md).

---

<div align="center">

[![Part of RazForge](https://img.shields.io/badge/Part%20of-RazForge-1a1a2e?style=for-the-badge&logo=github&logoColor=white&labelColor=16213e)](https://github.com/RazForge)

</div>
