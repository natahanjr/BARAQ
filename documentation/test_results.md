# BARAQ — Test Results

**Document:** Test Suite Execution Report
**Date:** 2026-08-31
**Environment:** Windows 11 · Python 3.13 · pytest 9.1.1 · PostgreSQL 16
**Command:** `python -m pytest tests -q`

---

## 1. Summary

```
1,300+ passed, 0 failed in ~45s
```

| Metric | Value |
|---|---|
| Total tests | **1,300+** |
| Passed | **1,300+** |
| Failed | 0 |
| Errors | 0 |
| Skips | 0 |

**Result: PASS**

---

## 2. Breakdown by Module

| Module | Tests | Covers |
|---|---|---|
| `tests/test_detection.py` | 100+ | All 100 native detection rules: brute force (T1110), suspicious PowerShell (T1059.001), privilege escalation (T1068), persistence (T1547), network recon (T1046), lateral movement, data staging, malware, phishing, DNS/HTTP exfil, USB, kill-chain correlation, credential access, registry, scheduled tasks, WMI, account tampering, masquerading, hidden artifacts, LOLBins, exfil volume, log clearing, Kerberos abuse, AD abuse, process abuse, defense evasion, exfil/C2; Sigma rule evaluation; alert enrichment and MITRE mapping |
| `tests/test_api.py` | 200+ | REST endpoints: dashboard summary/timeline/threat categories/severity/attack stats, alerts list/detail/status/notes/actions, events, investigation, assistant, reports, system status, evaluation, endpoints, incidents, threat intel, data export, search |
| `tests/test_collectors.py` | 100+ | Event log, process, network, PowerShell, Sysmon collectors + simulator scenarios (all 13 attack types + baseline); network bytes BIGINT verification |
| `tests/test_pipeline.py` | 200+ | Full pipeline: normalize → persist → detect → alert; scoring; security score; event normalization; ML train/score/analyze; Sigma evaluation; 100 native rules + 2,512 Sigma |
| `tests/test_risk.py` | 50+ | Hybrid Risk Scoring Engine: rule score scaling, ML anomaly averaging, 60/40 fusion, risk-level thresholds, descriptors, ensemble meta-learner |
| `tests/test_evaluation.py` | 50+ | Evaluation framework: confusion-matrix metrics, zero-division guards, full suite run (all scenarios detected, baseline clean, results persisted), hold-out evaluation |
| `tests/test_threat_intel.py` | 100+ | 9 threat intel providers: isbadip, FFraud, OTX, ThreatFox, URLhaus, MalwareBazaar, AbuseIPDB, FindIP, IPDetails; 3-tier loop, cache TTL |
| `tests/test_soar.py` | 50+ | SOAR actions: block_ip, kill_process, quarantine_file, disable_account, isolate_host; UAC elevation, error handling |
| `tests/test_export.py` | 50+ | Data export: 15 data types, CSV/JSON, streaming, filters |
| `tests/test_auth.py` | 100+ | Authentication, RBAC, MFA, SSO (OIDC/LDAP), CSRF, audit logging |
| `tests/test_ml.py` | 50+ | ML training, inference, drift detection, model persistence, feature engineering |
| `tests/test_database.py` | 50+ | PostgreSQL operations, BIGINT columns, migrations, retention |
| Other test modules | 200+ | Search language, saved searches, Sigma rules, alerts aggregation, incidents, streaming |

---

## 3. Detection Rule Validation

Rule validation uses the built-in attack simulator (realistic record streams), confirming:

| Rule | MITRE | Validated behavior | Expected | Actual |
|---|---|---|---|---|
| Brute Force | T1110 | ≥5 failed logons (4625) for same account in window | Alert HIGH | ✓ |
| Suspicious PowerShell | T1059.001 | Encoded command execution (4104) | Alert HIGH | ✓ |
| Privilege Escalation | T1068 | New admin account / privilege assignment | Alert HIGH | ✓ |
| Persistence | T1547 | Scheduled task / new service creation | Alert HIGH | ✓ |
| Network Reconnaissance | T1046 | Port probing (≥20 distinct ports) | Alert MEDIUM | ✓ |
| Kerberos Abuse | T1558.003 | Kerberoasting / AS-REP roasting / DCSync / Golden Ticket | Alert HIGH | ✓ |
| AD Abuse | T1087/T1484.001 | BloodHound collection / GPO modification | Alert HIGH | ✓ |
| Process Abuse | T1574.002/T1055 | DLL side-loading / process injection / token manipulation | Alert HIGH | ✓ |
| Defense Evasion | T1562.001/T1553.004 | Safe Mode tampering / AMSI bypass / rogue root cert | Alert HIGH | ✓ |
| Exfil/C2 | T1567.002/T1102.001/T1071.004 | Cloud upload / webhook dead-drop / DNS tunneling | Alert HIGH | ✓ |

No false positives observed for baseline (normal activity) scenarios in the test fixtures.

---

## 4. Evaluation Framework Results (hold-out, external validity)

The v3 hold-out evaluation (`backend/evaluation/holdout.py`) trains the ML
detector on a training split and measures detection on **unseen** attack
scenarios against a **real host-telemetry** baseline (340 live records).

| Metric | Rule layer | ML layer | Hybrid |
|---|---|---|---|
| Accuracy | **99.05%** | 89.58% | **99.05%** |
| Precision | **100%** | 100% | **100%** |
| Recall | **95.12%** | 64.29% | **95.12%** |
| F1-score | **0.975** | 0.783 | **0.975** |
| False positive rate | **0.0%** | 0.0% | **0.0%** |
| Detection time | ~70 ms | — | — |

> The v1 96.67% figure measured rules against the same synthetic data used to
> derive them and is superseded. The v3 numbers have external validity: rules
> detect 78 of 82 unseen attack records and raise zero alerts on 340 real host
> telemetry records. The 4 misses are in the `ml_c2_beacon` scenario (beacon-cadence
> features only partially scored by the network model).

Full methodology and per-scenario tables: `documentation/security_evaluation_report.md`.

---

## 5. API Validation (selected checks)

- `GET /api/health` → 200 OK
- `GET /api/dashboard/summary` → security score, KPIs, system status
- `GET /api/dashboard/user-behavior` · `detection-methods` · `risk-distribution` → 200 OK
- `GET /api/alerts` → paginated, filterable by status/severity
- `PATCH /api/alerts/{id}/status` → status workflow (open → investigating → resolved)
- `POST /api/alerts/{id}/notes` → analyst notes persisted
- `GET /api/investigation/alert/{id}` → attack chain + incident timeline + related events + network context
- `POST /api/assistant/chat` → local AI assistant reply
- `POST /api/reports/generate` → PDF/HTML/JSON/CSV files produced
- `POST /api/system/simulate` → records collected, findings raised, alerts created with hybrid risk scores
- `POST /api/evaluation/run` → per-scenario metrics + overall row persisted
- `GET /api/evaluation/latest` · `/results` → history

---

## 6. Live System Verification (2026-08-31)

Beyond unit/integration tests, the running platform was verified end-to-end:

| Check | Result |
|---|---|
| Backend live on `127.0.0.1:8001` | ✓ |
| `GET /api/health` → `{"status":"ok"}` | ✓ |
| Dashboard dev server on `http://localhost:5173` | ✓ |
| Vite proxy `/api/*` → backend (CORS pre-authorized) | ✓ |
| Live host collection (`POST /api/system/collect`) → 369 records | ✓ |
| Report generation through the UI API (technical PDF) | ✓ |
| Evaluation suite run via API (99.05% accuracy, 0% FPR) | ✓ |
| 100 native rules + 2,512 Sigma rules loaded | ✓ |
| 9 threat intel providers responding | ✓ |
| SOAR actions functional (Block IP, Kill Process, Quarantine, Disable Account, Isolate Host) | ✓ |
| Data export (CSV/JSON) for 15 data types | ✓ |
| Network bytes display (BIGINT — no overflow) | ✓ |
| ML model trained: 143,522 feature vectors, 3 streams | ✓ |
| ML drift state: WARNING (rate 0.75) | ✓ |

---

## 7. Notes

- 1 warning: Starlette deprecation notice for `httpx` in `fastapi.testclient` (upstream, non-blocking).
- Test DB is isolated via fixture (`tests/conftest.py`) — running the suite does not touch the live PostgreSQL database.
- The evaluation framework additionally uses its own isolated temporary database at runtime.
- Network bytes columns use BIGINT to handle Windows processes with >2GB I/O.
- ML system uses 3-layer detection: Isolation Forest + XGBoost/RandomForest + ensemble stacking meta-learner.
- Drift detection state: WARNING (ML_DRIFT_RATE=0.75).
