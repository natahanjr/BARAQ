# BARAQ — Test Results

**Document:** Test Suite Execution Report
**Date:** 2026-08-03
**Environment:** Windows 11 · Python 3.14 · pytest 9.1.1
**Command:** `python -m pytest tests -q`

---

## 1. Summary

```
48 passed, 1 warning in ~13s
```

| Metric | Value |
|---|---|
| Total tests | **48** |
| Passed | **48** |
| Failed | 0 |
| Errors | 0 |
| Skips | 0 |

**Result: PASS**

---

## 2. Breakdown by Module

| Module | Tests | Covers |
|---|---|---|
| `tests/test_detection.py` | 11 | All 5 detection rules: brute force (T1110), suspicious PowerShell (T1059.001), privilege escalation (T1068), persistence (T1547), network recon (T1046); alert enrichment and MITRE mapping (incl. parametrized rule checks) |
| `tests/test_api.py` | 9 | REST endpoints: dashboard summary/timeline/threat categories/severity/attack stats, alerts list/detail/status/notes, events, investigation, assistant, reports, system status |
| `tests/test_collectors.py` | 9 | Event log, process, network, PowerShell collectors + simulator scenarios (brute force, powershell, privilege escalation, persistence, port scan, baseline) (incl. parametrized scenario checks) |
| `tests/test_pipeline.py` | 9 | Full pipeline: normalize → persist → detect → alert; scoring; security score; event normalization; ML train/score/analyze |
| `tests/test_risk.py` | 6 | Hybrid Risk Scoring Engine: rule score scaling, ML anomaly averaging, 60/40 fusion, risk-level thresholds, descriptors |
| `tests/test_evaluation.py` | 4 | Evaluation framework: confusion-matrix metrics, zero-division guards, full suite run (all scenarios detected, baseline clean, results persisted) |

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

No false positives observed for baseline (normal activity) scenarios in the test fixtures.

---

## 4. Evaluation Framework Results (hold-out, external validity)

The v2 hold-out evaluation (`backend/evaluation/holdout.py`) trains the ML
detector on a training split and measures detection on **unseen** attack
scenarios against a **real host-telemetry** baseline (529 live records).

| Metric | Rule layer | ML layer | Hybrid |
|---|---|---|---|
| Accuracy | **100%** | 89.5% | **100%** |
| Precision | **100%** | 100% | **100%** |
| Recall | **100%** | 3.1% | **100%** |
| F1-score | **1.0** | 0.06 | **1.0** |
| False positive rate | **0.00%** | 0.00% | **0.00%** |
| Detection time | ~70 ms | — | — |

> The v1 96.67% figure measured rules against the same synthetic data used to
> derive them and is superseded. The v2 numbers have external validity: rules
> detect all 64 unseen attack records and raise zero alerts on 529 real host
> telemetry records.

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

## 6. Live System Verification (2026-08-03)

Beyond unit/integration tests, the running prototype was verified end-to-end:

| Check | Result |
|---|---|
| Backend live on `127.0.0.1:8000` | ✓ |
| `GET /api/health` → `{"status":"ok"}` | ✓ |
| Dashboard dev server on `http://localhost:5173` | ✓ |
| Vite proxy `/api/*` → backend (CORS pre-authorized) | ✓ |
| Live host collection (`POST /api/system/collect`) → 369 records | ✓ |
| Report generation through the UI API (technical PDF) | ✓ |
| Evaluation suite run via API (96.7% accuracy, 0% FPR) | ✓ |

---

## 7. Notes

- 1 warning: Starlette deprecation notice for `httpx` in `fastapi.testclient` (upstream, non-blocking).
- Test DB is isolated via fixture (`tests/conftest.py`) — running the suite does not touch the live `database/baraq.db`.
- The evaluation framework additionally uses its own isolated temporary database at runtime.
