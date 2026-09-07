# BARAQ — User Manual

**Document:** Operator Guide
**Version:** 3.0 (100 rules + Sigma, 9 threat intel, SOAR, data export, ML-enhanced)
**Audience:** SOC analyst / system administrator operating the platform

---

## 1. Introduction

BARAQ is a lightweight SOC platform that runs entirely on a single Windows 11 laptop. It collects real host telemetry, detects attacks via a rules engine and machine learning, maps threats to MITRE ATT&CK, visualizes everything in a SOC dashboard, and produces professional reports.

---

## 2. Quick Start

### 2.1 Prerequisites
- Windows 11, Python 3.13+, Node.js 18+ (frontend only)
- PostgreSQL 16+ on `127.0.0.1:5432` (required — no SQLite fallback)
- Backend dependencies: `pip install -r requirements.txt`
- Frontend dependencies: `cd frontend && npm install`

### 2.2 Start the backend
```powershell
.\start.bat
```
Or manually:
```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8001
```
The background scheduler begins collecting host telemetry and running detection every 15 seconds automatically.

### 2.3 Start the dashboard
```powershell
cd frontend
npm run dev
```
Open **http://localhost:5173**. The Vite dev proxy forwards `/api` → `http://127.0.0.1:8001`.

---

## 3. Dashboard Pages

### 3.1 Dashboard
- **Security score ring** (0–100) and **system status** (HEALTHY / ATTENTION / CRITICAL).
- KPI cards: total events, active alerts, critical threats, ML anomalies, **current risk level**.
- **Event & alert timeline (24 h)** — stacked area chart.
- **Threat categories** — bar chart of alerts per MITRE tactic.
- **Severity distribution** — donut chart of open alerts.
- **Attack statistics** — horizontal bar chart per attack type.
- **User behavior** — stacked successes/failures per account; **Detection method breakdown** — rule vs hybrid alerts.
- **Latest alerts** — click-through list; **Top targets** — most-hit accounts.
- Auto-refreshes every 15 seconds.

### 3.2 Alerts
- Filter by status (open / investigating / resolved / dismissed) and severity.
- Columns: alert (click for detail), severity, status, MITRE ID, tactic, evidence event count, detection time.
- Paginated (25 per page).

### 3.3 Alert Detail
- Description, **evidence** (raw finding text), **recommended action**.
- **Evidence events**: the raw normalized events that triggered the alert.
- **MITRE ATT&CK panel**: technique ID (links to attack.mitre.org), name, tactic, confidence, score.
- **Hybrid risk panel**: risk score (0-100), risk level (LOW→CRITICAL), detection method (rule-based or hybrid rule+ML).
- **Status workflow**: open → investigating → resolved / dismissed.
- **Analyst notes**: add notes; they persist and appear in investigation.

### 3.4 Investigation
- Select an alert → BARAQ reconstructs the **attack chain** (kill-chain steps: credential probing → access granted → privilege assignment → script execution → persistence ...).
- **Incident timeline**: visual sequence of surrounding events (Failed Login → Account Locked → ... → Alert Created).
- **Related events** within ±30 minutes of the first evidence event.
- **Network context** table for reconnaissance (T1046) alerts.
- **AI explanation** button: one-click natural-language analysis of the alert, displayed in a redesigned section with color-coded cards for severity, MITRE, IOCs, and recommendations. The analysis card includes an "AI Generated" badge and uses markdown table rendering for structured data.

### 3.5 MITRE ATT&CK
- Full ATT&CK matrix with 23 mapped techniques and 47 total techniques in the knowledge base.
- Clickable technique cards showing detection count, severity, and affected hosts.
- ML detection status bar (trained/stale/drift warning).
- Filter by tactic; search by technique ID or name.

### 3.7 Events
- Searchable/filterable table of normalized events: time, event ID, category, user, risk, ML anomaly flag, message.
- Filters: event ID (e.g. 4625), user, category, ML anomalies only.

### 3.8 Processes & Network
- **Processes**: PID, parent PID, image, user, "NEW" flag for new processes.
- **Network connections**: process, local/remote address:port, state, LISTEN flag, bytes sent/received (BIGINT — no overflow for large transfers).

### 3.9 Threat Intelligence
- **9 integrated providers**: isbadip.com, FFraud.com, AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar, AbuseIPDB, FindIP, IPDetails.io
- 3-tier provider loop: local cache → free providers → premium (abuse.ch)
- Professional source cards with provider status, response format, and query parameters
- No consumer language — designed for security analysts

### 3.10 SOAR Actions
- **Block IP**: Windows Firewall rule via `netsh advfirewall`
- **Kill Process**: `taskkill /F /PID` native Windows process termination
- **Quarantine File**: Moves files to `C:\BaraqQuarantine` with metadata
- **Disable Account**: `net user /active:no` native Windows command
- **Isolate Host**: Windows Firewall policy blocking all inbound/outbound
- All actions require UAC elevation (uses `Start-Process -Verb RunAs` when not running as admin)
- Confirmation modal with modern design before executing any action

### 3.11 Data Export
- Export any data type as CSV or JSON: events, alerts, processes, network, reports, incidents, evaluation runs, audit logs, assistant messages, endpoints, threat intel, dashboard snapshots, detection verdicts, sigma rules
- Live row counts per data type
- Filter by severity, status, search, date range
- Streaming download for large datasets

### 3.12 AI Assistant
- Chat with the local security assistant: explain alerts, summarize incidents, recommend remediation.
- Suggested prompts are provided; chat history persists in PostgreSQL.

### 3.13 Reports
- Choose **Executive** (security score, threat summary, risk level) or **Technical** (evidence, timeline, MITRE mappings, recommendations).
- Export as **PDF, HTML, JSON, or CSV**.
- Generated reports appear in the list with paths; files land in `reports/`.

### 3.14 Evaluation
- **Run detection evaluation**: runs brute force, PowerShell, privilege escalation, persistence, port scan + baseline through the full pipeline in an **isolated temporary database** (production data untouched).
- Results table per scenario: samples, TP/FP/TN/FN, **accuracy, precision, recall, F1-score, false-positive rate, detection time**.
- Overall metrics cards + per-scenario F1/recall and detection-time charts + run history.

### 3.15 System
- App status: version, database (PostgreSQL), collection state, uptime.
- **Collection & simulation**: run the full attack suite or a single scenario, or collect live host data.
- **Machine learning**: 3-layer detection system — Isolation Forest + XGBoost/RandomForest + Hybrid Risk Fusion (60% rules + 40% ML) + ensemble stacking meta-learner.
- Live KPI panel.
- **ML Status**: trained/stale/drift warning, 1300+ feature vectors from 129,170 events.

---

## 4. Typical Analyst Workflow

1. **Populate data** → System page → *Run simulation* (full suite) or *Collect live host data*.
2. **Triage** → Alerts page → filter by severity → open each alert.
3. **Investigate** → Alert Detail → read evidence and MITRE mapping → *Open investigation* → AI explanation → review attack chain.
4. **Respond** → set status (investigating / resolved), add analyst notes, run SOAR actions (Block IP, Kill Process, Quarantine File, Disable Account, Isolate Host).
5. **Export** → Data Export page → export events/alerts/processes as CSV or JSON for external analysis.
6. **Report** → Reports page → generate Executive PDF for stakeholders; Technical JSON/HTML for the engineering record.
7. **Monitor** → Dashboard page (auto-refreshes) and train the ML model from System page as events accumulate.

---

## 5. Command-Line Operations

```powershell
# Simulate the full attack suite
py -m backend.pipeline --simulate

# Simulate one scenario
py -m backend.pipeline --simulate brute_force
py -m backend.pipeline --simulate powershell
py -m backend.pipeline --simulate privilege_escalation
py -m backend.pipeline --simulate persistence
py -m backend.pipeline --simulate port_scan

# One live collection cycle
py -m backend.pipeline --collect
```

---

## 6. Configuration Cheat-Sheet (`backend/config.py`)

| Parameter | Default | Effect |
|---|---|---|
| `COLLECT_INTERVAL_SECONDS` | 15 | Scheduler interval |
| `BRUTE_FORCE_THRESHOLD` | 5 | Failed logons before brute-force alert |
| `PORT_SCAN_DISTINCT_PORTS` | 20 | Ports probed before recon alert |
| `DETECTION_WINDOW_MINUTES` | 10 | Correlation window for rules |
| `ML_CONTAMINATION` | 0.05 | IF anomaly rate |
| `ML_DRIFT_RATE` | 0.75 | Drift detection threshold (WARNING state) |
| `SECURITY_SCORE_PENALTY` | 14/8/4/1 | Score deduction per severity |

Environment variables: `BARAQ_INTERVAL`, `BARAQ_DATABASE_URL` (PostgreSQL), `BARAQ_AI_API_URL`, `BARAQ_AI_API_KEY`, `BARAQ_AI_MODEL`, `BARAQ_ABUSECH_KEY` (abuse.ch provider key).

---

## 7. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| Dashboard shows "Backend offline" | Backend not running; start uvicorn. Check `logs/server.err.log`. |
| No security events collected | Install/verify `pywin32` (`pip install pywin32`). Reading the **Security** log requires an elevated (Administrator) console — run the backend as admin for full event-log access. |
| Simulation produces no alerts | Run the *full suite*; single scenarios need matching rule thresholds (e.g. ≥5 failed logins). |
| PDF report fails | Verify `reportlab` installed and `reports/` directory writable. |
| Port 5173 busy | Change port in `frontend/vite.config.js` and matching `CORS_ORIGINS` in `backend/config.py`. |
| AI assistant gives generic answers | It is a local rule/TF-IDF engine by design; set `BARAQ_AI_API_URL`/`KEY` to delegate to the BARAQ AI endpoint for generative answers. |
| Alerts show "rule" not "hybrid" | Hybrid labels require ML scores on evidence events — train the model (System → ML → Train) and run **ML analyze** after collecting more data. |

---

## 8. File Locations

| Artifact | Path |
|---|---|
| PostgreSQL database | `sentinel` (port 5432) |
| ML model | `database/model_meta.json`, `database/model.bundle.joblib` |
| Generated reports | `reports/` |
| Logs | `logs/server.out.log`, `logs/server.err.log` |
| MITRE data | `backend/mitre/techniques.json` |
| Sigma rules | `backend/detection/sigma_rules/` (2,512 rules) |
| Threat intel cache | `database/threat_intel_cache.json` |
| Quarantine | `C:\BaraqQuarantine` |
| Tests | `tests/` (1,300+ tests) |
| Documentation | `documentation/` |
