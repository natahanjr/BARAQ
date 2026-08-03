# SentinelSOC

**SentinelSOC: An Intelligent Lightweight Security Operations Center Framework for Real-Time Windows Endpoint Threat Detection and Incident Analysis**

A complete, research-oriented SOC framework that runs entirely on a single Windows 11 laptop — no cloud, no heavy infrastructure. It collects real Windows telemetry, normalizes events, detects attacks with a **hybrid rule-based + machine-learning engine**, maps findings to MITRE ATT&CK, computes **hybrid risk scores**, displays everything in a professional SOC dashboard, generates executive/technical reports, and includes an **evaluation framework** that measures detection accuracy.

---

## Features

| Layer | Capabilities |
|---|---|
| **Collection** | Windows security event log (4624, 4625, 4720, 4726, 4732, 4740, 4672...), running/new processes with parent-child relationships, active TCP connections + listening ports, PowerShell operational log, plus a realistic attack simulator |
| **Processing** | Event normalization (Event ID / Category / User / Risk / Timestamp / Host) with **numeric risk scoring (0-100)** per event |
| **Rule-Based Detection** | 5 rules — Brute Force (T1110), Suspicious PowerShell (T1059.001), Privilege Escalation (T1068), Persistence (T1547), Network Reconnaissance (T1046) |
| **ML Detection** | Per-behavior anomaly analysis (**login / process / network**) with Isolation Forest + Random Forest / XGBoost supervised classifier |
| **Hybrid Risk Scoring** | Alert risk = **60% rule score + 40% ML anomaly score** → 0-100 score + LOW/MEDIUM/HIGH/CRITICAL level |
| **MITRE ATT&CK** | Every alert enriched with technique ID, name, tactic, confidence and recommendation |
| **Dashboard** | Security score, current risk level, system status, event/alert timeline, threat categories, severity distribution, attack statistics, user behavior, detection method breakdown, top targets, live alerts |
| **Investigation** | Attack-chain reconstruction (kill chain steps), incident timeline, related events ±30 min, network context, AI explanations |
| **AI Assistant** | Local rule/TF-IDF engine — explains alerts, summarizes incidents, recommends remediation, keeps chat history |
| **Reporting** | Executive & technical reports exported as **PDF, HTML, JSON, CSV** |
| **Evaluation Framework** | Runs all attack scenarios + baseline in an isolated DB; computes **accuracy, precision, recall, F1-score, false-positive rate, detection time** |
| **API** | Full FastAPI REST API with OpenAPI docs at `/docs` |

---

## Project Structure

```
SentinelSOC/
├── backend/
│   ├── ai/            # AI security assistant (local engine)
│   ├── analyzers/     # Normalizer (numeric risk) + dashboard analytics
│   ├── api/           # FastAPI routers (alerts, events, dashboard, evaluation, ...)
│   ├── collectors/    # Windows event log, process, network, PowerShell, simulator
│   ├── database/      # SQLAlchemy models + SQLite connection (+ additive migrations)
│   ├── detection/     # Rules engine, alerting (hybrid risk), 5 detection rules
│   ├── evaluation/    # Detection evaluation framework (metrics)
│   ├── mitre/         # MITRE ATT&CK techniques data + helpers
│   ├── ml/            # Isolation Forest / Random Forest / XGBoost anomaly detection
│   ├── reports/       # Report generator + exporters (PDF/HTML/JSON/CSV)
│   └── risk/          # Hybrid risk scoring engine (rule 60% + ML 40%)
├── frontend/          # React 18 + Tailwind CSS 4 + Recharts dashboard
├── database/          # Local SQLite database (sentinel.db)
├── logs/              # Runtime logs
├── reports/           # Generated security reports
├── tests/             # pytest test suite (48 tests)
├── documentation/     # User manual, DB schema, architecture, test results, evaluation report
├── requirements.txt
└── README.md
```

---

## Requirements

- **Windows 10/11** (target: Windows 11, Intel i5, minimum 8GB RAM, any SSD)
- **Python 3.11+** (tested with 3.14)
- **Node.js 18+** (tested with 24) — only required for the dashboard
- Optional: `pywin32` for full Windows Event Log access (installed automatically on Windows)

---

## Installation

### 1. Backend

```powershell
# from the project root
python -m venv venv
venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### 2. Frontend

```powershell
cd frontend
npm install
```

---

## Running the Platform

### Start the backend API

```powershell
# from the project root (with venv activated)
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

The backend starts a background scheduler (every 15 s) that collects host telemetry and runs detection automatically.

- API: `http://127.0.0.1:8000`
- Interactive API docs (Swagger): `http://127.0.0.1:8000/docs`
- Health check: `http://127.0.0.1:8000/api/health`

### Start the SOC dashboard

```powershell
cd frontend
npm run dev
```

Open **http://localhost:5173** — the dashboard auto-connects to the backend via the Vite proxy (no extra configuration).

### Production-style build (optional)

```powershell
cd frontend
npm run build     # outputs static bundle to frontend/dist
npm run preview   # serve the built bundle
```

---

## Quick Start: Generate Your First Alerts

1. Start the backend and the dashboard (above).
2. In the dashboard, open **System → Run simulation** (or use the API):

```powershell
# Full attack suite (brute force, PowerShell, privesc, persistence, port scan)
curl.exe -X POST http://127.0.0.1:8000/api/system/simulate -H "Content-Type: application/json" -d "{}"

# Single scenario
curl.exe -X POST http://127.0.0.1:8000/api/system/simulate -H "Content-Type: application/json" -d "{\"scenario\":\"brute_force\"}"
```

3. Open **Alerts** to review detections; click any alert for MITRE mapping, evidence and recommended action.
4. Open **Investigation**, select an alert, and inspect its attack chain; use **AI explanation**.
5. Open **Reports**, choose Executive/Technical + PDF/HTML/JSON/CSV and click **Generate report**.

### Collect real host telemetry

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/system/collect
```

### Train and run the ML anomaly detector

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/system/ml/train
curl.exe -X POST http://127.0.0.1:8000/api/system/ml/analyze
```

### Run the detection evaluation framework

```powershell
# Runs brute force, PowerShell, privesc, persistence, port scan + baseline
# through the full pipeline in an isolated temporary DB, then reports:
# accuracy, precision, recall, F1-score, false-positive rate, detection time
curl.exe -X POST http://127.0.0.1:8000/api/evaluation/run
curl.exe http://127.0.0.1:8000/api/evaluation/latest
```

The same workflow is available in the dashboard under **Evaluation**.

---

## Running Tests

```powershell
# from the project root (with venv activated)
python -m pytest tests -v
```

Result: **48 tests passed** (collectors, detection rules, pipeline, API, hybrid risk scoring, evaluation framework).

---

## Configuration

All tunable parameters live in `backend/config.py`:

| Setting | Default | Purpose |
|---|---|---|
| `COLLECT_INTERVAL_SECONDS` | 15 | Scheduler collection interval |
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logons within window → alert |
| `PORT_SCAN_DISTINCT_PORTS` | 20 | Distinct probed ports → alert |
| `DETECTION_WINDOW_MINUTES` | 10 | Detection correlation window |
| `ML_CONTAMINATION` | 0.05 | Isolation Forest contamination |
| `SECURITY_SCORE_PENALTY` | critical 14 / high 8 / medium 4 / low 1 | Score deduction per open alert |

Environment overrides: `SENTINEL_INTERVAL`, `SENTINEL_DATABASE_URL`, `SENTINEL_AI_API_URL`, `SENTINEL_AI_API_KEY`, `SENTINEL_AI_MODEL`.

---

## Security Score

- Starts at **100**; each open alert deducts points by severity (critical 14, high 8, medium 4, low 1).
- `HEALTHY` ≥ 70 · `ATTENTION` 40–69 · `CRITICAL` < 40.

## Hybrid Risk Scoring

For every alert the platform computes a **hybrid risk score (0-100)**:

```
Final Risk = 0.6 × RuleScore(severity, confidence, event count)
           + 0.4 × MLScore(mean anomaly score of evidence events)

Risk levels:  LOW (<40) · MEDIUM (40-64) · HIGH (65-84) · CRITICAL (≥85)
```

Rule-only alerts are labelled `rule`; alerts whose evidence carries ML
anomaly scores are labelled `hybrid`. Weights are configurable in
`backend/config.py` (`ML_RULE_WEIGHT`, `ML_DETECTION_WEIGHT`).

---

## Documentation

See `documentation/` for:

- `user_manual.md` — complete operator guide
- `database_schema.md` — schema, tables and ER notes
- `architecture.md` — system architecture, data flow, and ASCII diagram
- `test_results.md` — test suite results and coverage summary
- `security_evaluation_report.md` — detection metrics (accuracy/precision/recall/F1/FPR/detection time)

---

## Thesis Support

This repository is the working prototype for the MSc thesis:

> *"SentinelSOC: An Intelligent Lightweight Security Operations Center Framework for Real-Time Windows Endpoint Threat Detection and Incident Analysis"*

Suggested thesis sections it supports: threat collection methodology (Module 1), normalization design (Module 2), rule-based detection (Module 3), ML anomaly detection (Module 4), hybrid risk scoring (Module 5), MITRE ATT&CK alignment (Module 6), SOC dashboard UX (Module 7), AI-assisted analysis (Module 8), automated reporting (Module 9), and the evaluation framework with detection metrics (Module 10).
