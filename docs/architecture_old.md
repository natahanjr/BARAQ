# BARAQ — System Architecture

**Document:** Architecture Overview
**Version:** 3.0 (100 rules + Sigma, 9 threat intel, SOAR, data export, ML-enhanced)
**Scope:** BARAQ v3.0 (single Windows 11 laptop, PostgreSQL backend)

---

## 1. High-Level Architecture

```
                    ┌────────────────────────────────────────────┐
                    │              WINDOWS 11 HOST               │
                    │                                            │
                    │   ┌────────────────────────────────────┐   │
│   │        BARAQ Backend         │   │
│   │        (FastAPI / Uvicorn)         │   │
│   │              :8001                 │   │
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
                    │  │ Detection   │      │  IF / XGB /  │     │
                    │  │(100+S rules)│      │  Meta-learner│     │
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
                    │   │   (SQLite: baraq.db)            │   │
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
- **Rules Engine** (`rules_engine.py`) runs 100 native detection rules + 2,512 Sigma rules against the current corpus within a correlation window (default 10 minutes).
- **Native Rules** (`detection/rules/`):

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
| `kerberos.py` | Kerberoasting (4769 RC4 / Rubeus), AS-REP roasting (4768 no-preauth), DCSync (4662 replication / secretsdump), Golden & Silver tickets (krbtgt 4768 / admin RC4 4769), Pass-the-Hash (NTLM type-3 logons / sekurlsa::pth), Pass-the-Ticket (Kerberos type-9/10 / kerberos::ptt) | T1558.003 / T1558.004 / T1003.006 / T1558.001 / T1558.002 / T1550.002 / T1550.003 |
| `ad_abuse.py` | BloodHound/SharpHound collection, GPO modification (5136 CN=Policies / SharpGPOAbuse) | T1087 / T1484.001 |
| `process_abuse.py` | DLL side-loading (Sysmon 7 module outside System32), process injection (Sysmon 8 CreateRemoteThread), token manipulation (token::elevate), PrintNightmare (printui.dll /ia, Add-PrinterDriver) | T1574.002 / T1055 / T1134 / T1068 |
| `defense_evasion.py` | Safe Mode boot tampering (bcdedit safeboot), AMSI/Defender bypass strings (4104), rogue root-cert install (certutil -addstore, New-SelfSignedCertificate) | T1562.001 / T1562.001 / T1553.004 |
| `exfil_c2.py` | Cloud-storage uploads (rclone/aws s3/azcopy), webhook dead-drop C2 (Slack/Teams/Discord/Telegram), DNS tunneling (long labels, per-process query volume, TXT-sized responses) | T1567.002 / T1102.001 / T1071.004 |

- **Alerting Service** (`alerting.py`) deduplicates findings into `Alert` records, linking evidence events (many-to-many), attaching MITRE metadata + recommendations, and computing the **hybrid risk score** for every alert.
- **ML** (`ml/anomaly.py`): three-layer lightweight anomaly detection:
  1. Per-behavior **Isolation Forest** (login / process / network streams),
  2. Supervised **Random Forest / XGBoost** classifier (attack vs baseline clusters; XGBoost used when installed, sklearn fallback otherwise),
  3. Per-event anomaly score (0-1) feeding the hybrid risk engine.
- **Hybrid Risk Scoring** (`risk/scoring.py`): `Final = 0.6 × rule(severity, confidence, events) + 0.4 × ML(mean anomaly of evidence)` → 0-100 with LOW/MEDIUM/HIGH/CRITICAL levels. Alerts are labelled `rule` or `hybrid` by `detection_method`.

### 2.4 MITRE ATT&CK (`backend/mitre/`)
`attack.py` + `techniques.json` provide technique name, tactic, and recommended response for every mapped technique (T1046, T1059.001, T1068, T1110, T1547, plus T1078, T1036, T1497, T1005, T1027, T1040, T1555 fallbacks).

### 2.5 Database (`backend/database/`)
PostgreSQL via psycopg3 + SQLAlchemy 2.0. 47+ tables including: `users`, `normalized_events`, `alerts`, `alert_events`, `analyst_notes`, `processes`, `network_connections` (BIGINT bytes), `dashboard_snapshots`, `evaluation_runs`, `assistant_messages`, `reports`, `incidents`, `incident_links`, `incident_comments`, `audit_log`, `detection_verdicts`, `reputation_cache`, `saved_searches`, `search_panels`, `sigma_rules`, `endpoints`, `agent_commands`, `threat_intel_cache`, and more. Retention default 30 days.

### 2.6 SOC Dashboard (`frontend/`)
React 18 + Tailwind CSS 4 + Recharts, served by Vite on port 5173. Talks to the backend exclusively through the Vite dev proxy (`/api` → `127.0.0.1:8001`), so no CORS issues and no configuration. Pages: Dashboard, Alerts, Alert Detail, Investigation, Events, Processes & Network, Threat Intelligence, MITRE ATT&CK, AI Assistant, Reports, Evaluation, System, Data Export.

### 2.7 Report Generation (`backend/reports/`)
`generator.py` builds an executive or technical report context from live DB analytics; `exporters.py` renders PDF (ReportLab), HTML, JSON, and CSV into `reports/`. Metadata stored in the `reports` table.

### 2.8 AI Assistant (`backend/ai/`)
`assistant.py` implements a fully local engine (intent matching + TF-IDF keyword retrieval against a threat knowledge base in `knowledge.py`). It can explain alerts, summarize incidents, recommend remediation, and produce analyst notes. Optional: delegate to the BARAQ AI endpoint via `BARAQ_AI_API_URL` env vars.

### 2.9 Evaluation Framework (`backend/evaluation/`)
Runs the five attack scenarios + baseline through the complete pipeline (normalize → persist → rules → alert) inside an **isolated temporary database** (production data is never touched), then computes per-scenario and overall detection metrics:

- Accuracy, precision, recall, F1-score, false-positive rate, detection time (ms).

Results persist to `evaluation_runs` for reporting and history. Exposed via `/api/evaluation/*` and the **Evaluation** page in the dashboard.

### 2.10 SOAR Actions (`backend/response/`)
Real Windows-native security response actions executed via PowerShell:
- **Block IP**: `netsh advfirewall firewall add rule` — adds inbound deny rule
- **Kill Process**: `taskkill /F /PID` — force-terminates process
- **Quarantine File**: moves file to `C:\BaraqQuarantine` with metadata JSON
- **Disable Account**: `net user /active:no` — disables local Windows account
- **Isolate Host**: `netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound` — blocks all traffic
- All actions require UAC elevation via `Start-Process -Verb RunAs`

### 2.11 Threat Intelligence (`backend/threatintel/`)
9 integrated providers in a 3-tier loop:
1. **Local cache** (1-hour TTL) → 2. **Free providers** (isbadip, FFraud, AlienVault OTX, AbuseIPDB, FindIP, IPDetails.io) → 3. **Premium providers** (ThreatFox, URLhaus, MalwareBazaar — require `BARAQ_ABUSECH_KEY`)

### 2.12 Data Export (`backend/api/export.py`)
Universal CSV/JSON export for all 15 data types: events, alerts, processes, network, reports, incidents, evaluation runs, audit logs, assistant messages, endpoints, threat intel, dashboard snapshots, detection verdicts, sigma rules, and alerts with evidence. Supports streaming for large datasets.

### 2.13 Data Layer Migrations (`backend/database/connection.py`)
`init_db()` performs additive in-place migrations on existing SQLite files (new columns on `events`/`alerts`, new tables), so upgrading an older BARAQ database is seamless.

---

## 3. Data Flow (one collection cycle)

```
Collectors → raw records
   ↓
Normalizer → NormalizedEvent (risk 0-100) / ProcessRecord / NetworkConnection
   ↓
RulesEngine.evaluate(window) → 100 native rules + 2,512 Sigma rules → DetectionResults
   ↓
MITRE enrichment (technique, tactic, recommendation) + Threat Intel lookups (9 providers)
   ↓
Hybrid Risk Scoring → Alert (risk_score, risk_level, detection_method)
   ↓
ML analyze → event ml_score / is_anomaly (feeds future hybrid scores) + drift detection
   ↓
Dashboard analytics (KPIs, timelines, distributions, user behavior)
   ↓
Dashboard UI (REST)  ·  Report generator (PDF/HTML/JSON/CSV)  ·  Evaluation framework
   ↓
SOAR actions (Block IP, Kill Process, Quarantine, Disable Account, Isolate Host)
   ↓
Data Export (CSV/JSON for all data types)
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

Interactive docs: `http://127.0.0.1:8001/docs`.

---

## 5. Resource Footprint (low-resource design)

- **DB:** PostgreSQL on port 5432 (local or fleet-scale).
- **Scheduler:** single background thread, 15 s interval.
- **ML:** 3-layer system — Isolation Forest + XGBoost/RandomForest + ensemble stacking meta-learner. Trained on local data, no GPU.
- **AI assistant:** local rule/TF-IDF engine; no LLM required by default.
- **Sigma rules:** 2,512 YAML rules loaded on startup, cached in memory.
- **Expected footprint:** < 400 MB RAM total for backend + dashboard during normal operation on an i5 / 12 GB laptop.
