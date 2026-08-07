# SentinelSOC — System Architecture

**Document:** Architecture Overview
**Version:** 2.0 (upgraded: hybrid risk scoring + ML + evaluation framework)
**Scope:** SentinelSOC v1.1 prototype (single Windows 11 laptop)

---

## 1. High-Level Architecture

```
                    ┌────────────────────────────────────────────┐
                    │              WINDOWS 11 HOST               │
                    │                                            │
                    │   ┌────────────────────────────────────┐   │
                    │   │        SentinelSOC Backend         │   │
                    │   │        (FastAPI / Uvicorn)         │   │
                    │   │              :8000                 │   │
                    │   └───────────────┬────────────────────┘   │
                    │                   │                        │
                    │   ┌───────────────▼────────────────────┐   │
                    │   │        Event Collection Layer      │   │
                    │   │  eventlog │ process │ network │ PS │   │
                    │   │  (+ attack simulator)             │   │
                    │   └───────────────┬────────────────────┘   │
                    │                   │                        │
                    │   ┌───────────────▼────────────────────┐   │
                    │   │        Security Data Processing    │   │
                    │   │  Normalizer → risk 0-100 → DB      │   │
                    │   └───────────────┬────────────────────┘   │
                    │                   │                        │
                    │        ┌──────────┴──────────┐             │
                    │        ▼                     ▼             │
                    │  ┌─────────────┐      ┌──────────────┐     │
                    │  │ Rule-Based  │      │  ML Engine   │     │
                    │  │ Detection   │      │  IF / RF /   │     │
                    │  │ (5 rules)   │      │  XGBoost     │     │
                    │  └──────┬──────┘      └──────┬───────┘     │
                    │         └─────────┬──────────┘             │
                    │                   ▼                        │
                    │  ┌──────────────────────────────────────┐  │
                    │  │       Hybrid Risk Scoring Engine     │  │
                    │  │    0.6 × rule + 0.4 × ML = 0-100     │  │
                    │  │    LOW · MEDIUM · HIGH · CRITICAL    │  │
                    │  └───────────────────┬──────────────────┘  │
                    │                      ▼                     │
                    │   ┌────────────────────────────────────┐   │
                    │   │        MITRE ATT&CK Mapper         │   │
                    │   │  technique · tactic · rec action   │   │
                    │   └───────────────────┬────────────────┘   │
                    │                      ▼                     │
                    │   ┌────────────────────────────────────┐   │
                    │   │         Local Database             │   │
                    │   │   (SQLite: sentinel.db)            │   │
                    │   └───────────┬────────────┬───────────┘   │
                    │               │            │               │
                    │      ┌────────▼───┐  ┌─────▼─────────┐     │
                    │      │ SOC        │  │ Evaluation    │     │
                    │      │ Dashboard  │  │ Framework     │     │
                    │      │ :5173      │  │ (isolated DB) │     │
                    │      └────────────┘  └───────────────┘     │
                    │                                            │
                    │   ┌────────────────────────────────────┐   │
                    │   │      Incident Report Generator     │   │
                    │   │  PDF · HTML · JSON · CSV           │   │
                    │   └────────────────────────────────────┘   │
                    │                                            │
                    └────────────────────────────────────────────┘
```

---

## 2. Component Description

### 2.1 Event Collection Layer (`backend/collectors/`)
| Collector | Source | Output |
|---|---|---|
| `eventlog.py` | Windows Security/System Event Log (pywin32) | Login success (4624), login failure (4625), account creation (4720), privilege changes (4732/4672), scheduled tasks (4698), services (7045) |
| `process.py` | psutil process snapshot | Running processes, PID/PPID, parent-child, new process detection |
| `network.py` | psutil net connections | Active TCP connections, remote IPs, listening ports |
| `powershell.py` | PowerShell Operational log | PowerShell executions (4104), encoded/download/hidden command patterns |
| `simulator.py` | Synthetic record generator | Realistic attack datasets for all 5 detection scenarios + baseline |

The `CollectorManager` (`collectors/__init__.py`) orchestrates all collectors. A scheduler thread in `backend/main.py` runs the full collection + detection loop every 15 seconds.

### 2.2 Log Processing Engine (`backend/analyzers/`)
`normalizer.py` converts raw records into a uniform schema:

```
Event ID: 4625          Category: Authentication
User: Admin             Risk: Medium
Severity: medium        Timestamp: 2026-08-03T07:12:00Z
Host: <hostname>        Message: <normalized text>     Raw: <original record>
```

Risk mapping: event ID → risk level; severity derived per category (Authentication/Recon = medium+...). All events are persisted via `NormalizedEvent` and flagged `is_anomaly` by the ML layer.

### 2.3 Threat Detection & Analysis (`backend/detection/`, `backend/ml/`, `backend/risk/`)
- **Rules Engine** (`rules_engine.py`) instantiates the five rules and runs each against the current corpus within a correlation window (default 10 minutes).
- **Rules** (`detection/rules/`):

| Rule | Detection logic | MITRE |
|---|---|---|
| `brute_force.py` | ≥5 failed logons (4625) for same account in window | T1110 |
| `powershell.py` | Encoded (-EncodedCommand/-e), download-execute (IEX/DownloadString), hidden execution | T1059.001 |
| `privilege_escalation.py` | New admin accounts, sensitive privilege assignment (4720/4732/4672) | T1068 |
| `persistence.py` | Run-key registry changes, scheduled tasks, new services (4698/7045) | T1547 |
| `network_recon.py` | One source probing ≥20 distinct ports in 120 s | T1046 |
| `lateral_movement.py` | SMB connections + cross-host logons | T1021 |
| `data_staging.py` | Archive tools against data folders (7z/rar/zip) | T1074 |
| `malware_file.py` | Known-bad hash/path/signature hits | T1105 |
| `email_phishing.py` | Heuristic sender/attachment/body scoring | T1566 |
| `dns_http.py` | DNS tunnel/TLD + oversized HTTP bodies | T1071 |
| `usb.py` | New removable-device insertion | T1091 |
| `correlation.py` | ≥2 kill-chain steps from one host in window | T1082 |
| `vulnerability.py` | Installed software matching known CVEs | T1190 |
| `credential_access.py` | Sysmon E10 targeting lsass.exe from unexpected process | T1003.001 |
| `registry_runkey.py` | Sysmon E13 writes to Run/RunOnce autostart keys | T1547.001 |
| `scheduled_task.py` | schtasks /create with masquerading name / writable action path | T1053.005 |
| `wmi_event_subscription.py` | wmic/PowerShell subscription object creation | T1546.003 |
| `account_tampering.py` | Password reset/deletion/enable of admin accounts | T1098 |
| `masquerading.py` | System-named binary running outside C:\Windows | T1036 |
| `hidden_artifacts.py` | ADS (:stream) + attrib +h hiding | T1564 |
| `lolbin_execution.py` | rundll32/mshta/regsvr32/certutil/bitsadmin abuse | T1218 |
| `exfiltration_volume.py` | Per-process HTTP volume > 5 MB / 250 req | T1041 |
| `log_clearing.py` | Event 1102/104 clears + .evtx deletion | T1070.001 |

- **Alerting Service** (`alerting.py`) deduplicates findings into `Alert` records, linking evidence events (many-to-many), attaching MITRE metadata + recommendations, and computing the **hybrid risk score** for every alert.
- **ML** (`ml/anomaly.py`): three-layer lightweight anomaly detection:
  1. Per-behavior **Isolation Forest** (login / process / network streams),
  2. Supervised **Random Forest / XGBoost** classifier (attack vs baseline clusters; XGBoost used when installed, sklearn fallback otherwise),
  3. Per-event anomaly score (0-1) feeding the hybrid risk engine.
- **Hybrid Risk Scoring** (`risk/scoring.py`): `Final = 0.6 × rule(severity, confidence, events) + 0.4 × ML(mean anomaly of evidence)` → 0-100 with LOW/MEDIUM/HIGH/CRITICAL levels. Alerts are labelled `rule` or `hybrid` by `detection_method`.

### 2.4 MITRE ATT&CK (`backend/mitre/`)
`attack.py` + `techniques.json` provide technique name, tactic, and recommended response for every mapped technique (T1046, T1059.001, T1068, T1110, T1547, plus T1078, T1036, T1497, T1005, T1027, T1040, T1555 fallbacks).

### 2.5 Local Database (`backend/database/`)
SQLite at `database/sentinel.db` via SQLAlchemy 2.0. Seven tables (see `database_schema.md`). Retention default 30 days.

### 2.6 SOC Dashboard (`frontend/`)
React 18 + Tailwind CSS 4 + Recharts, served by Vite on port 5173. Talks to the backend exclusively through the Vite dev proxy (`/api` → `127.0.0.1:8000`), so no CORS issues and no configuration. Pages: Dashboard, Alerts, Alert Detail, Investigation, Events, Processes & Network, AI Assistant, Reports, System.

### 2.7 Report Generation (`backend/reports/`)
`generator.py` builds an executive or technical report context from live DB analytics; `exporters.py` renders PDF (ReportLab), HTML, JSON, and CSV into `reports/`. Metadata stored in the `reports` table.

### 2.8 AI Assistant (`backend/ai/`)
`assistant.py` implements a fully local engine (intent matching + TF-IDF keyword retrieval against a threat knowledge base in `knowledge.py`). It can explain alerts, summarize incidents, recommend remediation, and produce analyst notes. Optional: delegate to an OpenAI-compatible endpoint via `SENTINEL_AI_API_URL` env vars.

### 2.9 Evaluation Framework (`backend/evaluation/`)
Runs the five attack scenarios + baseline through the complete pipeline (normalize → persist → rules → alert) inside an **isolated temporary SQLite database** (production data is never touched), then computes per-scenario and overall detection metrics:

- Accuracy, precision, recall, F1-score, false-positive rate, detection time (ms).

Results persist to `evaluation_runs` for reporting and history. Exposed via `/api/evaluation/*` and the **Evaluation** page in the dashboard.

### 2.10 Data Layer Migrations (`backend/database/connection.py`)
`init_db()` performs additive in-place migrations on existing SQLite files (new columns on `events`/`alerts`, new tables), so upgrading an older SentinelSOC database is seamless.

---

## 3. Data Flow (one collection cycle)

```
Collectors → raw records
   ↓
Normalizer → NormalizedEvent (risk 0-100) / ProcessRecord / NetworkConnection
   ↓
RulesEngine.evaluate(window) → DetectionResults
   ↓
MITRE enrichment (technique, tactic, recommendation)
   ↓
Hybrid Risk Scoring → Alert (risk_score, risk_level, detection_method)
   ↓
ML analyze → event ml_score / is_anomaly (feeds future hybrid scores)
   ↓
Dashboard analytics (KPIs, timelines, distributions, user behavior)
   ↓
Dashboard UI (REST)  ·  Report generator (PDF/HTML/JSON/CSV)  ·  Evaluation framework
```

---

## 4. REST API Surface

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Health check |
| `GET /api/dashboard/summary` | KPIs + security score |
| `GET /api/dashboard/timeline?hours=` | Event/alert timeline buckets |
| `GET /api/dashboard/threat-categories` | Alerts per MITRE tactic |
| `GET /api/dashboard/severity-distribution` | Alerts per severity |
| `GET /api/dashboard/attack-stats` | Alerts per attack name |
| `GET /api/dashboard/top-attackers` | Top targeted accounts |
| `GET /api/dashboard/user-behavior` | Per-user login success/failure/avg risk |
| `GET /api/dashboard/detection-methods` | Alerts by detection method (rule/hybrid) |
| `GET /api/dashboard/risk-distribution` | Alerts by risk level |
| `GET /api/alerts?status=&severity=&page=` | Alert list (paginated, filterable) |
| `GET /api/alerts/{id}` | Alert detail + evidence events + notes |
| `PATCH /api/alerts/{id}/status` | Update alert status |
| `POST /api/alerts/{id}/notes` | Add analyst note |
| `GET /api/events?event_id=&user=&category=&anomaly=` | Normalized events |
| `GET /api/processes` / `GET /api/network` | Telemetry tables |
| `GET /api/events/statistics` | Aggregates by event ID/category |
| `GET /api/investigation/alert/{id}` | Attack chain + related events + network context |
| `POST /api/assistant/chat` · `GET /api/assistant/history` | AI chat |
| `POST /api/assistant/explain` · `POST /api/assistant/summarize` | AI actions |
| `POST /api/reports/generate` · `GET /api/reports/list` | Report generation |
| `POST /api/system/collect` | One live collection cycle |
| `POST /api/system/simulate` | Run attack simulation |
| `POST /api/system/ml/train` · `POST /api/system/ml/analyze` · `GET /api/system/ml/status` | ML lifecycle |
| `POST /api/evaluation/run` | Run detection evaluation suite (isolated DB) |
| `GET /api/evaluation/results` · `GET /api/evaluation/latest` | Evaluation history / latest run |
| `GET /api/system/status` | App status + KPIs + uptime |

Interactive docs: `http://127.0.0.1:8000/docs`.

---

## 5. Resource Footprint (low-resource design)

- **DB:** SQLite file, no server process.
- **Scheduler:** single background thread, 15 s interval.
- **ML:** Isolation Forest — small in-memory model, trained on local data, no GPU.
- **AI assistant:** local rule/TF-IDF engine; no LLM required by default.
- **Expected footprint:** < 300 MB RAM total for backend + dashboard during normal operation on an i5 / 12 GB laptop.
