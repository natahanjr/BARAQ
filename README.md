# BARAQ

AI-Powered Security Operations Platform for Windows endpoints.

> Self-hosted SOC: telemetry collection, hybrid rule + ML detection, MITRE ATT&CK mapping, investigation, SOAR automation, threat intelligence, and AI-assisted analysis.

[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React%2018-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)

---

## Quick Start

### Requirements

- **Windows 10/11**
- **Python 3.13+**
- **Node.js 18+** (for dashboard build)
- **PostgreSQL 16+** on `127.0.0.1:5432`

### Launch

```powershell
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
.\start.bat
```

On first run: creates venv, installs deps, builds dashboard, provisions PostgreSQL, generates bootstrap ML model, prints admin credentials, starts backend on `http://127.0.0.1:8001`.

### URLs

| What | URL |
|---|---|
| Dashboard | `http://127.0.0.1:8001` |
| API docs | `http://127.0.0.1:8001/docs` |
| Health check | `http://127.0.0.1:8001/api/health` |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13+, FastAPI, SQLAlchemy, psycopg3 |
| Frontend | React 18, Tailwind CSS 4, Recharts, WebSocket |
| Database | PostgreSQL 16+ |
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
├── frontend/          # React 18 dashboard
├── scripts/           # Agent, build, seed_demo, sigma_pull, tune
├── tests/             # 1,300+ tests
└── docs/              # Full documentation suite
```

---

## Running Tests

```powershell
python -m pytest tests -v
```

---

## Documentation

| Document | Description |
|---|---|
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
| OTRF Security-Datasets | 100K+ | JSON/CSV | [OTRF](https://github.com/OTRF/Security-Datasets) |
| BOTSv1 | 1.8M | CSV | [Splunk](https://github.com/splunk/botsv1) |
| BOTES | 2M+ | CSV | [Splunk](https://github.com/splunk/botes) |

View imported dataset statistics:
```bash
curl -X GET "http://localhost:8001/api/datasets/status" \
  -H "Authorization: Bearer <token>"
```

---

## License

Copyright (c) 2026 [Natahan](https://github.com/natahanjr) — [RazForge Lab](https://github.com/natahanjr)

Licensed under the [RazForge License](https://github.com/RazForge/.github/blob/main/RAZFORGE-SOURCE-AVAILABLE-LICENSE.md).

---

<div align="center">

[![Part of RazForge](https://img.shields.io/badge/Part%20of-RazForge-1a1a2e?style=for-the-badge&logo=github&logoColor=white&labelColor=16213e)](https://github.com/RazForge)

</div>
