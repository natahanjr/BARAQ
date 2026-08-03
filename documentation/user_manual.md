# SentinelSOC — User Manual

**Document:** Operator Guide
**Version:** 2.0 (hybrid risk scoring + evaluation framework)
**Audience:** SOC analyst / thesis examiner operating the prototype

---

## 1. Introduction

SentinelSOC is a lightweight SOC platform that runs entirely on a single Windows 11 laptop. It collects real host telemetry, detects attacks via a rules engine and machine learning, maps threats to MITRE ATT&CK, visualizes everything in a SOC dashboard, and produces professional reports.

---

## 2. Quick Start

### 2.1 Prerequisites
- Windows 11, Python 3.11+, Node.js 18+ (frontend only)
- Backend dependencies: `pip install -r requirements.txt`
- Frontend dependencies: `cd frontend && npm install`

### 2.2 Start the backend
```powershell
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
The background scheduler begins collecting host telemetry and running detection every 15 seconds automatically.

### 2.3 Start the dashboard
```powershell
cd frontend
npm run dev
```
Open **http://localhost:5173**.

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
- Select an alert → SentinelSOC reconstructs the **attack chain** (kill-chain steps: credential probing → access granted → privilege assignment → script execution → persistence ...).
- **Incident timeline**: visual sequence of surrounding events (Failed Login → Account Locked → ... → Alert Created).
- **Related events** within ±30 minutes of the first evidence event.
- **Network context** table for reconnaissance (T1046) alerts.
- **AI explanation** button: one-click natural-language analysis of the alert.

### 3.5 Events
- Searchable/filterable table of normalized events: time, event ID, category, user, risk, ML anomaly flag, message.
- Filters: event ID (e.g. 4625), user, category, ML anomalies only.

### 3.6 Processes & Network
- **Processes**: PID, parent PID, image, user, "NEW" flag for new processes.
- **Network connections**: process, local/remote address:port, state, LISTEN flag.

### 3.7 AI Assistant
- Chat with the local security assistant: explain alerts, summarize incidents, recommend remediation.
- Suggested prompts are provided; chat history persists (stored in SQLite).

### 3.8 Reports
- Choose **Executive** (security score, threat summary, risk level) or **Technical** (evidence, timeline, MITRE mappings, recommendations).
- Export as **PDF, HTML, JSON, or CSV**.
- Generated reports appear in the list with paths; files land in `reports/`.

### 3.9 Evaluation
- **Run detection evaluation**: runs brute force, PowerShell, privilege escalation, persistence, port scan + baseline through the full pipeline in an **isolated temporary database** (production data untouched).
- Results table per scenario: samples, TP/FP/TN/FN, **accuracy, precision, recall, F1-score, false-positive rate, detection time**.
- Overall metrics cards + per-scenario F1/recall and detection-time charts + run history.

### 3.10 System
- App status: version, database, collection state, uptime.
- **Collection & simulation**: run the full attack suite or a single scenario, or collect live host data.
- **Machine learning**: train the Isolation Forest model, analyze recent events, view model status.
- Live KPI panel.

---

## 4. Typical Analyst Workflow

1. **Populate data** → System page → *Run simulation* (full suite) or *Collect live host data*.
2. **Triage** → Alerts page → filter by severity → open each alert.
3. **Investigate** → Alert Detail → read evidence and MITRE mapping → *Open investigation* → AI explanation → review attack chain.
4. **Respond** → set status (investigating / resolved), add analyst notes.
5. **Report** → Reports page → generate Executive PDF for stakeholders; Technical JSON/HTML for the engineering record.
6. **Monitor** → Dashboard page (auto-refreshes) and train the ML model from System page as events accumulate.

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
| `SECURITY_SCORE_PENALTY` | 14/8/4/1 | Score deduction per severity |

Environment variables: `SENTINEL_INTERVAL`, `SENTINEL_DATABASE_URL`, `SENTINEL_AI_API_URL`, `SENTINEL_AI_API_KEY`, `SENTINEL_AI_MODEL`.

---

## 7. Troubleshooting

| Symptom | Cause / Fix |
|---|---|
| Dashboard shows "Backend offline" | Backend not running; start uvicorn. Check `logs/server.err.log`. |
| No security events collected | Install/verify `pywin32` (`pip install pywin32`). Reading the **Security** log requires an elevated (Administrator) console — run the backend as admin for full event-log access. |
| Simulation produces no alerts | Run the *full suite*; single scenarios need matching rule thresholds (e.g. ≥5 failed logins). |
| PDF report fails | Verify `reportlab` installed and `reports/` directory writable. |
| Port 5173 busy | Change port in `frontend/vite.config.js` and matching `CORS_ORIGINS` in `backend/config.py`. |
| AI assistant gives generic answers | It is a local rule/TF-IDF engine by design; set `SENTINEL_AI_API_URL`/`KEY` to delegate to an OpenAI-compatible endpoint for generative answers. |
| Alerts show "rule" not "hybrid" | Hybrid labels require ML scores on evidence events — train the model (System → ML → Train) and run **ML analyze** after collecting more data. |

---

## 8. File Locations

| Artifact | Path |
|---|---|
| SQLite database | `database/sentinel.db` |
| Generated reports | `reports/` |
| Logs | `logs/server.out.log`, `logs/server.err.log` |
| MITRE data | `backend/mitre/techniques.json` |
| Tests | `tests/` |
| Documentation | `documentation/` |
