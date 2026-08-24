# BARAQ — Database Schema

**Document:** Database Schema & ER Reference
**Version:** 2.0 (adds hybrid risk fields + evaluation runs)
**Engine:** SQLite (`database/baraq.db`) via SQLAlchemy 2.0 ORM
**Models:** `backend/database/models.py`

---

## 1. Entity Overview

```
events ────< alert_events >──── alerts ────< analyst_notes
               │                              │
               │                              └── evaluation_runs (independent)
processes
network_connections
dashboard_snapshots
assistant_messages
```

> **Migration:** existing BARAQ databases are upgraded automatically at
> startup (`init_db` in `backend/database/connection.py`) — new columns and
> tables are added in place without data loss.

---

## 2. Tables

### 2.1 `events` — NormalizedEvent
The atomic unit of the pipeline: a normalized security event.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| event_id | INTEGER, idx | Windows Event ID (4624, 4625, 4720, 4732, 4672, 4104, 4698, 7045, ...) |
| category | TEXT(64), idx | Authentication / Account / Process / Persistence / Network / Scripting / Other |
| source | TEXT(32), idx | eventlog / process / network / powershell / simulator |
| user | TEXT(128), idx | Account associated with the event ("-" if none) |
| host | TEXT(128) | Hostname of the source machine |
| risk | TEXT(16), idx | Low / Medium / High |
| severity | TEXT(16), idx | info / low / medium / high / critical |
| message | TEXT | Human-readable normalized description |
| timestamp | DATETIME, idx | Event time (UTC, tz-aware) |
| raw_json | JSON | Original raw collector record |
| is_anomaly | BOOLEAN, idx | Flagged by ML detector |
| ml_score | FLOAT | Anomaly score from Isolation Forest (0–1) |
| risk_score | FLOAT, idx | Numeric risk 0-100 from the normalizer (base band + aggravating modifiers) |

### 2.2 `alerts` — Alert
A detection finding enriched with MITRE ATT&CK context.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| name | TEXT(128), idx | e.g. "Brute Force Attack" |
| description | TEXT | Rule description |
| severity | TEXT(16), idx | critical / high / medium / low / info |
| status | TEXT(16), idx | open / investigating / resolved / dismissed |
| confidence | FLOAT | Rule confidence 0–1 |
| score | FLOAT | Severity-based score (critical 10, high 7, medium 4, low 1) |
| mitre_id | TEXT(16), idx | T1110, T1059.001, T1068, T1547, T1046 |
| mitre_name | TEXT(128) | ATT&CK technique name |
| mitre_tactic | TEXT(64) | Initial Access / Execution / Privilege Escalation / Persistence / Discovery |
| recommendation | TEXT | Analyst recommended response |
| evidence | TEXT | Human-readable evidence summary |
| rule | TEXT(64), idx | Rule ID that produced the alert |
| event_count | INTEGER | Number of linked evidence events |
| detection_method | TEXT(16), idx | rule / hybrid (rule + ML) / ml |
| risk_score | FLOAT, idx | Hybrid risk score 0-100 (0.6×rule + 0.4×ML) |
| risk_level | TEXT(16), idx | LOW / MEDIUM / HIGH / CRITICAL |
| created_at | DATETIME, idx | UTC |
| updated_at | DATETIME | UTC, on update |

### 2.3 `alert_events` — AlertEventLink
Many-to-many link between alerts and evidence events.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| alert_id | INTEGER FK → alerts.id | CASCADE on delete, idx |
| event_id | INTEGER FK → events.id | CASCADE on delete, idx |
| | | UNIQUE (alert_id, event_id) |

### 2.4 `processes` — ProcessRecord
Snapshot of a running/new process observed by the process collector.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| pid | INTEGER, idx | Process ID |
| ppid | INTEGER | Parent process ID |
| name | TEXT(256), idx | Image name |
| path | TEXT | Executable path |
| command_line | TEXT | Full command line (from raw record) |
| parent_name | TEXT(256) | Parent image name |
| user | TEXT(128) | Owning user |
| is_new | BOOLEAN | True when first seen in this collection window |
| observed_at | DATETIME, idx | UTC |

### 2.5 `network_connections` — NetworkConnection
Observed TCP connection or listening socket.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| pid | INTEGER | Owning process ID |
| process | TEXT(256) | Owning process name |
| local_ip | TEXT(64) | Local address |
| local_port | INTEGER | Local port |
| remote_ip | TEXT(64), idx | Remote address |
| remote_port | INTEGER | Remote port |
| state | TEXT(32) | ESTABLISHED / LISTEN / SYN_SENT ... |
| is_listening | BOOLEAN | True for LISTEN sockets |
| observed_at | DATETIME, idx | UTC |

### 2.6 `dashboard_snapshots` — DashboardSnapshot
Periodic KPI roll-ups for historical trending.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | DATETIME, idx | UTC |
| security_score | FLOAT | 0–100 |
| total_events | INTEGER | |
| active_alerts | INTEGER | |
| critical_threats | INTEGER | |
| events_last_hour | INTEGER | |

### 2.7 `reports` — ReportRecord
Metadata for every generated report file.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| report_type | TEXT(32) | executive / technical |
| format | TEXT(16) | pdf / html / json / csv |
| title | TEXT(256) | Report title |
| file_path | TEXT | Absolute path in `reports/` |
| created_at | DATETIME | UTC |

### 2.8 `analyst_notes` — AnalystNote
Analyst annotations attached to alerts during investigation.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| alert_id | INTEGER FK → alerts.id | CASCADE on delete |
| note | TEXT | Free-text note |
| created_at | DATETIME | UTC |

### 2.9 `evaluation_runs` — EvaluationRun
One evaluation-framework run per scenario (plus an `overall` roll-up row).

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| scenario | TEXT(64), idx | brute_force / powershell / privilege_escalation / persistence / port_scan / baseline / overall |
| total_samples | INTEGER | Attack + baseline samples |
| attack_samples | INTEGER | Ground-truth positive events |
| baseline_samples | INTEGER | Ground-truth negative events |
| true_positives | INTEGER | Attack events detected |
| false_positives | INTEGER | Baseline events flagged |
| true_negatives | INTEGER | Baseline events not flagged |
| false_negatives | INTEGER | Attack events missed |
| accuracy | FLOAT | (TP+TN)/total |
| precision | FLOAT | TP/(TP+FP) |
| recall | FLOAT | TP/(TP+FN) |
| f1_score | FLOAT | Harmonic mean of precision & recall |
| false_positive_rate | FLOAT | FP/(FP+TN) |
| detection_time_ms | FLOAT | First attack event → first alert (mean) |
| created_at | DATETIME | UTC |

### 2.10 `assistant_messages` — AssistantMessage
Chat history for the AI security assistant.

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| role | TEXT(16) | user / assistant |
| content | TEXT | Message body |
| created_at | DATETIME | UTC |

---

## 3. Relationships

- `Alert 1 ──< AlertEventLink >── 1 NormalizedEvent` (many-to-many evidence links)
- `Alert 1 ──< AnalystNote` (one-to-many, cascade delete)
- `EvaluationRun` is independent (evaluation framework uses its own isolated database at runtime).
- All foreign keys use `ON DELETE CASCADE`.

## 4. Conventions

- Timestamps stored UTC, timezone-aware (`DateTime(timezone=True)`), serialized as ISO 8601.
- Raw records preserved in `events.raw_json` for forensics and reprocessing.
- Default retention: 30 days (`EVENT_RETENTION_DAYS` in `backend/config.py`).
