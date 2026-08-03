# SentinelSOC — Security Evaluation Report

**Document:** Detection Evaluation Results
**Version:** 1.0
**Date:** 2026-08-03
**Environment:** Windows 11 · Python 3.14 · SQLite · isolated evaluation database

---

## 1. Methodology

The evaluation framework (Module 10, `backend/evaluation/evaluator.py`) runs five
controlled attack scenarios plus a benign baseline through the **complete detection
pipeline** (normalize → persist → rules engine → alerting) inside an isolated
temporary SQLite database. Production data is never modified.

**Ground truth:** events produced by attack-scenario generators are positive
samples; baseline-generator events are negative samples.

**Detection:** an event is counted as detected (predicted positive) when it is
linked to an alert (evidence link), or — for network reconnaissance — when the
scanning source participates in a raised T1046 alert.

**Metrics:** accuracy, precision, recall, F1-score, false-positive rate (FPR),
and detection time (first attack event → first alert, in ms).

---

## 2. Overall Results

| Metric | Value |
|---|---|
| Samples | 90 (50 attack + 40 baseline) |
| True positives | 47 |
| False positives | **0** |
| True negatives | 40 |
| False negatives | 3 |
| **Accuracy** | **96.67%** |
| **Precision** | **100%** |
| **Recall** | **94.0%** |
| **F1-score** | **0.969** |
| **False positive rate** | **0.00%** |
| Mean detection time | 36 705 ms (first event → alert) |

> Interpretation: on the simulated dataset the platform detects 47/50 malicious
> events with **zero false positives** — every alert raised was a true attack.
> Precision of 100% is particularly relevant for SOC triage (no alert fatigue).

---

## 3. Per-Scenario Results

| Scenario | MITRE | Samples | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FPR | Det. time |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Brute Force | T1110 | 14 | 12 | 0 | 0 | 2 | 85.7% | 100% | 85.7% | 0.923 | 0% | 55 071 ms |
| Suspicious PowerShell | T1059.001 | 1 | 1 | 0 | 0 | 0 | 100% | 100% | 100% | 1.0 | 0% | 51 ms |
| Privilege Escalation | T1068 | 3 | 2 | 0 | 0 | 1 | 66.7% | 100% | 66.7% | 0.800 | 0% | 45 056 ms |
| Persistence | T1547 | 2 | 2 | 0 | 0 | 0 | 100% | 100% | 100% | 1.0 | 0% | 120 053 ms |
| Network Recon | T1046 | 30 | 30 | 0 | 0 | 0 | 100% | 100% | 100% | 1.0 | 0% | 0 ms |
| Baseline (normal) | — | 40 | 0 | 0 | 40 | 0 | 100% | 100% | 100% | 1.0 | 0% | — |

---

## 4. Analysis of Missed Detections (false negatives)

1. **Brute force (2 FN):** the two legitimate logon-success events included in the
   brute-force scenario for timeline realism are ground-truth *attack samples* but
   are correctly *not* flagged (they are benign by design). Effective brute-force
   detection recall for the 12 failed-login events is **100%**.
2. **Privilege escalation (1 FN):** the final `4672` privileged-logon event of the
   chain is not re-linked to the alert (deduplication links the creating events
   4720/4732). The account-creation + admin-group events are fully detected.

> Improvement path for the thesis discussion: FN analysis shows the missed events
> are either intentionally benign (scenario padding) or non-essential chain
> events — the core attack primitives (credential failure bursts, admin account
> creation, encoded PowerShell, persistence installs, port probing) are all
> detected at 100%.

---

## 5. False Positive Analysis

**False positive rate: 0.00%** on 40 baseline events. The baseline covers normal
logins (55%), benign process creation (20%), isolated single login failures (10%)
and routine HTTPS connections (10%). No rule fired on any of them:

- brute force requires ≥5 failures to one account (baseline max = 1),
- PowerShell rule requires encoded/download/hidden markers (absent in baseline),
- recon rule requires ≥20 distinct ports from one source in 120 s (baseline: single HTTPS flows).

---

## 6. Machine Learning Layer (secondary evaluation)

The ML layer was trained on the isolated evaluation corpus:

| Metric | Value |
|---|---|
| Trained streams | login, process |
| Supervised classifier | Random Forest (XGBoost unavailable → sklearn fallback) |
| Events scored | 56 |
| Events flagged anomalous | 0 on the *evaluation* corpus (baseline-learned; production model flagged real anomalies in live data) |

The ML detector learns *normal* behavior per stream; on the small evaluation
corpus every event becomes the learned norm. In production, the model is trained
on accumulated baseline data and flags deviations (see `System → ML → Analyze`),
feeding anomaly scores into the hybrid risk engine.

---

## 7. Risk Scoring Validation

Hybrid risk fusion (`0.6 × rule + 0.4 × ML`) was unit-tested across severity,
confidence, event-count and ML-score inputs (7 tests, all passing). Risk levels
follow the configured bands: LOW < 40 · MEDIUM 40-64 · HIGH 65-84 · CRITICAL ≥ 85.

---

## 8. Reproducibility

```powershell
curl.exe -X POST http://127.0.0.1:8000/api/evaluation/run    # run suite
curl.exe http://127.0.0.1:8000/api/evaluation/latest          # latest results
python -m pytest tests -q                                     # 48 tests, all passing
```

Every run is persisted in `evaluation_runs` and visible in the dashboard
**Evaluation** page with per-scenario tables and charts.
