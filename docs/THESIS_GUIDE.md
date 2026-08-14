# Academic Research & Thesis Guide

This guide helps you turn the BARAQ project into a rigorous academic deliverable
(a thesis, dissertation, or research paper). It maps the implemented system,
the measured results, and the project's internal tooling onto the standard
structure of a computer-science / cybersecurity thesis, and tells you exactly
what evidence you already have and how to reproduce or extend it.

It is a writing scaffold: every section below corresponds to a real capability,
dataset, or measurement that exists in this repository. Replace the guidance
text with your own writing, but keep the numbers, claims, and limits accurate
(see "Research ethics & integrity").

---

## 1. Suggested working titles

Pick one or adapt:

1. **A Lightweight Hybrid Detection System Combining Rule-Based and Machine-Learning Analysis for University Laboratory Networks** (system-focused)
2. **BARAQ: Design and Evaluation of an Offline-Operable SOC Platform for Resource-Constrained Academic Environments** (design-science focused)
3. **Improving Threat Detection in Small Academic Networks: A Case Study of Sigma-Rule Integration with Statistical Anomaly Detection** (integration-focused)
4. **Hybrid Rule and ML Detection on Host Telemetry: Implementation and Empirical Evaluation of BARAQ** (empirical-evaluation focused)

The exact framing should come from your department's thesis handbook and your
supervisor. A common pattern is `Verb Phrase: System + Context`.

---

## 2. Research questions

The project evidence supports answering the following research questions.
Map each question to one or more thesis chapters (see section 8):

- **RQ1 (Architecture)**: How can a full SOC (collection, normalization,
  detection, alerting, MFA-secured console) be delivered as a self-contained,
  offline-operable package for a university laboratory network?
  *Evidence: `dist\BARAQ-Setup-1.0.0.exe`, architecture in README; single-host
  deployment with portable PostgreSQL 16 on port 55432; TLS agent intake on
  port 8443; PyInstaller packaging; runs without external internet access
  except the optional AI assistant.*
- **RQ2 (Detection coverage)**: What detection coverage is achieved by
  combining 43 native detection rules with 2,413 Sigma rules
  (2,407 SigmaHQ community rules + 6 curated rules) and a statistical ML
  anomaly layer?
  *Evidence: 75 live findings; 30+ open alerts from one Sigma rule family;
  holdout evaluation in section 5.*
- **RQ3 (Detection quality)**: What accuracy/precision/recall does the hybrid
  detector achieve on held-out attack scenarios while producing no false
  positives on real host telemetry?
  *Evidence: holdout evaluation results, section 5.*
- **RQ4 (Operational performance)**: What is the end-to-end performance of the
  system (API latency, ingest throughput, Sigma evaluation time, memory
  footprint) on a mid-range Windows workstation?
  *Evidence: performance measurements, section 6.*

**Recommendation**: add one design question (RQ1) and one empirical question
(RQ3) as primary; use RQ2/RQ4 as supporting. Do not phrase RQs as yes/no
questions.

---

## 3. Literature review map

Your literature review should be built around the following concrete topics.
For each topic, search academic databases (Google Scholar, IEEE Xplore, ACM DL,
Scopus) using the given search terms, then organise sources into the review
chapter. **Do not invent citations** — only cite sources you have actually read
and that exist (see integrity note in section 9).

| Topic | What to read about | Search terms |
|---|---|---|
| SIEM & SOC foundations | SIEM architecture, log management, correlation | "SIEM architecture", "log correlation", "security operations center", "log management NIST" |
| Rule-based detection | Detection engineering, rule quality, false-positive management | "detection engineering", "signature-based detection false positives" |
| Sigma | The Sigma rule specification and SigmaHQ repository | "Sigma rules specification", "SigmaHQ", "sigma rule format SIEM" |
| MITRE ATT&CK | Attack taxonomy used for mapping detections to techniques | "MITRE ATT&CK framework", "ATT&CK mapping detection engineering" |
| Anomaly / ML detection | Statistical and unsupervised anomaly detection on host telemetry | "unsupervised anomaly detection network security", "isolation forest intrusion detection", "autoencoder intrusion detection", "credential brute force detection" |
| Hybrid detection | Combining signature/rule and ML methods | "hybrid intrusion detection rule machine learning", "ensemble detection SIEM" |
| Authentication security | Password hashing (PBKDF2, RFC 8018), TOTP (RFC 6238), RBAC | "PBKDF2 password storage", "TOTP two-factor RFC 6238", "role based access control web application" |
| Windows host telemetry | Windows Event Log channels, Sysmon | "Windows Event Log Security channel", "Sysmon event collection", "event ID 4688 process creation" |
| Benchmarking | Detection evaluation methodology, precision/recall/F1 | "intrusion detection evaluation metrics", "false positive rate detection benchmark" |

**Standards and primary sources you can cite directly** (these are real and
public): MITRE ATT&CK (attack.mitre.org), SigmaHQ/sigma GitHub repository,
Sigma rule specification, RFC 8018 (PBKDF2), RFC 6238 (TOTP), NIST SP 800-63B
(authentication), NIST SP 800-92 (log management). Verify the exact edition and
access date per your citation style.

---

## 4. Methodology chapter template

Use the implemented system and its tooling as the described method. The
following is a proven structure; adapt wording to your university's template.

### 4.1 Research approach
Describe the approach as **design science research combined with empirical
evaluation**: an artefact (the BARAQ platform) was designed and implemented,
then evaluated in two ways — (a) controlled detection-quality evaluation with
held-out attack scenarios and real-telemetry negatives, and (b) operational
performance measurement on a live deployment. Justify this choice: the artefact
itself is the contribution, so design science applies; the measurements provide
the empirical evidence.

### 4.2 Environment
- **Host platform**: Windows 11 workstation; Python 3.13 runtime; FastAPI +
  Uvicorn (HTTPS on port 8443 for agent intake, TLS 1.2/1.3 with a self-signed
  certificate whose SANs cover localhost and the LAN addresses).
- **Database**: portable PostgreSQL 16.6 (compiled VC++ 1942), port 55432,
  `max_connections=50`, 29 schema tables after migration.
- **Frontend**: React + Vite single-page application served by the backend
  (development server on port 5173).
- **Collection sources**: Windows Event Log channels — Security, System,
  Microsoft-Windows-PowerShell/Operational, Windows PowerShell, and
  Microsoft-Windows-Sysmon/Operational; plus agent-reported process, network,
  DNS, HTTP, email, USB, malware, and vulnerability records.
- **Packaging**: PyInstaller 6 one-dir bundle with an Inno Setup installer
  (`BARAQ-Setup-1.0.0.exe`) that provisions PostgreSQL, the application
  database, credentials, and logon autostart.

### 4.3 Detection architecture (what you built)
Describe the layered pipeline: collect → normalize → persist → detect → alert.
- **Normalization**: a `Normalizer` coerces heterogeneous raw records into a
  canonical `NormalizedEvent` schema (fields incl. `NewProcessName`,
  `ParentProcessName`, `CommandLine`, `cmdline_len`, `account_name`,
  `has_encoded`).
- **Rule layer**: 43 native rules + a Sigma engine executing 2,413 Sigma
  rules. Rules map detections to MITRE ATT&CK techniques and produce
  recommendations via `get_recommendation`. Findings feed an `AlertingService`
  that deduplicates/throttles duplicates (evidence: alert #108 as a throttled
  refresh of one PowerShell-encoded-command family).
- **ML layer**: a statistical anomaly detector trained on login/process
  features and network IP buckets; `detector` frozen after training split
  (see section 5).
- **Security controls**: PBKDF2-HMAC-SHA256 (260,000 iterations) password
  hashing, TOTP MFA with admin-enforcement flag, DPAPI-backed secret vault,
  RBAC (admin/analyst), per-tenant attribution via agent org mapping.

### 4.4 Evaluation protocol (already implemented — reproduce it)
- **Unit/integration tests**: pytest suite of **623 tests, 1 warning,
  ~19 min** on this machine; run with:
  ```
  venv\Scripts\python.exe -m pytest tests -q
  ```
  Note: tests set `SIGMA_RULES_DIR` to an empty temp dir (see
  `tests/conftest.py`) so the Sigma engine is not exercised in the fast suite;
  Sigma-specific behaviour is covered by `tests/test_sigma.py`.
- **Holdout evaluation** (the core empirical study): `backend/evaluation/holdout.py`
  splits 20 attack scenarios into a **training split (9 scenarios)** and a
  **holdout split (11 scenarios)**; the ML detector is trained only on the
  training split; the negative class is **375 records of real host telemetry**;
  scoring is per-sample with rule, ML, and hybrid layers reported separately;
  results persist to the production DB. Run it with:
  ```
  venv\Scripts\python.exe -c "from backend.database.connection import get_db; from backend.evaluation.holdout import run_holdout_evaluation; import json; db=next(get_db()); print(json.dumps(run_holdout_evaluation(db, with_ml=True, use_real_baseline=True, randomize=True), indent=2, default=str)); db.close()"
  ```
  (~144 s runtime, includes seeded domain randomization, seed 20260806.)
- **Performance measurement**: the figures in section 6 were measured against
  the live HTTPS backend (port 8443) using synthetic agent batches through
  `POST /api/ingest` and repeated authenticated API calls; the persist-only
  rate was isolated by instrumenting the pipeline directly.

---

## 5. Results you can already report

All figures below were measured in this project and are reproducible. Report
them exactly; do not inflate them.

### 5.1 Detection quality (holdout evaluation)

| Layer | Samples | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 | FP-rate |
|---|---|---|---|---|---|---|---|---|---|---|
| Rule (43 native + 2,413 Sigma) | 457 | 78 | 0 | 375 | 4 | 99.1% | 100% | 95.1% | 0.975 | 0.0% |
| ML anomaly | 50 | 9 | 0 | 36 | 5 | 90.0% | 100% | 64.3% | 0.783 | 0.0% |
| Hybrid | 457 | 78 | 0 | 375 | 4 | 99.1% | 100% | 95.1% | 0.975 | 0.0% |

Holdout scenarios (11, never used in training): port scan, lateral movement,
data staging, phishing, USB, DNS exfiltration, HTTP exfiltration, malware,
ML masquerade, ML C2 beacon, ML lateral C2 — **all detected by the rule layer**
(78/78 positives, including ML-scoped scenarios caught via complementary rules
such as `masquerading`, `suspicious_powershell`, `c2_beacon`).

Training scenarios (9): brute force, PowerShell abuse, privilege escalation,
persistence, credential spray, obfuscated PowerShell, implant drop, hidden
script, network exfiltration.

Negative class: 375 real host telemetry records → **0 false positives**.

### 5.2 Live-detection evidence
- 17,365 events collected in the development database (live collection plus
  an earlier imported set).
- 83 open alerts at final measurement; alert #108 demonstrated throttling of
  duplicate detections (one Sigma rule family).
- System status transitioned HEALTHY → CRITICAL as Sigma alerts accumulated —
  usable evidence for alert-lifecycle behaviour, but note the severity math
  (score 0.0 under high alert volume) as a limitation.

### 5.3 Test suite
623 tests passing (1 warning) in ~19 min — evidence of implementation
correctness, not detection efficacy. Use it in a "software quality" subsection.

---

## 6. Operational performance results

Measured against the live HTTPS (TLS 8443) backend, warm Sigma cache, 17k+
events, on the development workstation.

| Metric | Value |
|---|---|
| Login (PBKDF2-260k verification) | 457 ms p50, 680 ms avg |
| `GET /api/system/health` | 27 ms avg |
| `GET /api/events?limit=20` | 78 ms avg |
| `GET /api/alerts?limit=20` | 272 ms avg (46 ms p50) |
| `GET /api/system/status` (aggregation) | 1,229 ms avg |
| **Ingest throughput (full pipeline incl. Sigma)** | **1–3 events/s** |
| Ingest persist-only path | 469 events/s |
| Sigma engine cold load (2,413 YAMLs) | 36.4 s (then cached per process) |
| Scheduler cycle (window work) | ~0.5 s per cycle (462 records, 0 alerts observed) |
| Backend memory (working set) | 271 MB (686 MB private) |
| PostgreSQL memory (9 processes) | 431 MB |

**Interpretation for the thesis**: persist throughput is two orders of
magnitude above the detection-bound ingest rate, which is dominated by
re-evaluating the full 10-minute window against all 2,413 Sigma rules per
request (measured 44–71 s per batch). Frame this as a design trade-off
(detect-on-ingest for low-latency alerting vs. throughput), acceptable for the
target deployment (a small laboratory fleet, batches every 30–60 s), and list
"incremental Sigma evaluation" as future work.

---

## 7. Discussion & limitations (be honest)

Write these into your discussion chapter; they strengthen rather than weaken
the thesis:

1. **Detection-bound ingest**: full-window Sigma re-evaluation per ingest
   request limits throughput to 1–3 events/s (see section 6). Not a problem
   for the target scale; a documented optimization path exists.
2. **ML layer recall is modest (64.3%)**: the ML layer is a complement to
   rules; on held-out ML-scoped scenarios the rule layer still detected
   everything. Frame ML as an additional signal, not the primary detector.
3. **Legacy imported data is obfuscated**: older 4688 records are
   `sentinel-v1:` obfuscated blobs and do not carry the structured fields live
   collection provides; longitudinal analyses should use live-collected data
   only.
4. **Single-instance design**: the server holds a single-instance lock; a
   clustered/multi-node deployment is out of scope.
5. **Self-signed TLS**: the certificate used is self-signed (CN localhost,
   SANs covering LAN addresses) — valid for lab use; production would require
   a trusted PKI.
6. **No external validation yet**: results are from one environment. External
   validity (other networks, other attacker profiles) is future work.
7. **Alert-severity aggregation**: security score reaches 0.0 when alert
   volume is high (observed after Sigma alerts accumulated); the scoring
   function is a candidate for refinement.

---

## 8. Suggested thesis outline

A common European-style structure (adjust to your faculty's template):

| Chapter | Content | Rough length |
|---|---|---|
| 1. Introduction | Motivation (small institutions need affordable SOC), problem statement, RQs (section 2), contributions, thesis outline | 6–10 pp |
| 2. Background & related work | Literature review per section 3; classify related systems (commercial SIEMs vs open-source vs research prototypes) | 12–20 pp |
| 3. System design | Requirements, architecture, detection pipeline, security controls (section 4) | 12–18 pp |
| 4. Implementation | Key modules (collector, normalizer, rules engine, Sigma engine, ML detector, alerting, console), packaging/deployment | 10–15 pp |
| 5. Evaluation | Protocol (4.4), results (5, 6) | 8–12 pp |
| 6. Discussion | Limitations (7), comparison with related work, threats to validity | 6–10 pp |
| 7. Conclusion & future work | Answers to RQs, contributions (9), future work | 3–6 pp |
| References | Follow department style (APA/IEEE) | — |
| Appendices | Architecture diagram, configuration reference, rule catalogue, test inventory, installer manifest | — |

**Time plan suggestion**: chapters 1–2 first (writing proceeds while figures
are re-run), chapter 5 needs the least writing time because the evidence is
ready — write it early and ask your supervisor for feedback on the results
before writing chapters 3–4.

---

## 9. Research ethics & integrity (required)

- **Run everything on your own lab infrastructure only.** The evaluation uses
  synthetic attack fixtures executed against controlled hosts and real
  telemetry from machines you administer. Never deploy detection artefacts or
  attack simulations on networks you do not own or have explicit permission
  to test.
- **Personal data**: log data may contain usernames, IP addresses and host
  names. If the thesis reports live telemetry, pseudonymise or aggregate it
  (e.g., "user A", host ranges) and state this in the methodology.
- **Do not fabricate citations or data.** Every figure in sections 5–6 was
  actually measured in this repository and is reproducible with the commands
  given. Cite only sources you have read. Your university's plagiarism policy
  applies to the thesis text, code, and data.
- **AI use disclosure**: if your institution requires it, disclose the use of
  AI assistants in the writing/development process as mandated by your
  university's policy.
- **Liability**: describe the system as a detection aid, not an automated
  response system; it notifies operators and does not block or remediate.

---

## 10. Contributions (for the introduction/conclusion)

1. A self-contained, offline-operable SOC platform delivered as a single
   installer for Windows laboratory networks (collection, detection, alerting,
   MFA-secured console in one artefact).
2. A hybrid detection pipeline combining native rules, a 2,413-rule Sigma
   engine (SigmaHQ + curated rules), and a statistical ML anomaly layer,
   with per-rule MITRE ATT&CK mapping and recommendations.
3. An empirical evaluation protocol (held-out attack scenarios, real-telemetry
   negative class, randomized fixtures) and its results: 99.1% accuracy /
   100% precision / 95.1% recall at zero false positives on the rule layer.
4. A reproducibility kit: 380 automated tests and reproducible performance
   measurements (section 6).

---

## 11. Reproducibility kit (copy into your appendix)

```powershell
# 1. Full test suite
venv\Scripts\python.exe -m pytest tests -q

# 2. Sigma-focused tests
venv\Scripts\python.exe -m pytest tests\test_sigma.py -q

# 3. Holdout evaluation (persists metrics to the DB)
venv\Scripts\python.exe -c "<command from section 4.4>"

# 4. Pull Sigma rules (needs internet)
venv\Scripts\python.exe scripts\sigma_pull.py

# 5. Performance probe (adjust host/port/credentials)
venv\Scripts\python.exe <your perf script against https://127.0.0.1:8443>

# 6. Release build
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_release.ps1
```

Document in the appendix: hardware/OS of the test machine, Python/PostgreSQL
versions, commit hash of the code used, date of each measurement run, and the
exact seed used for randomization (20260806).

---

## 12. Writing tips specific to this project

- Use the **Results → Discussion → Conclusion** discipline: report measured
  numbers (section 5–6) without adjectives; reserve interpretation for the
  Discussion.
- Define every metric before using it: accuracy, precision, recall, F1,
  false-positive rate, and the measurement methodology (per-request latency,
  p50/p95) in the evaluation chapter.
- When describing the Sigma engine, cite the Sigma specification and
  SigmaHQ repository; when describing MITRE mapping, cite ATT&CK; when
  describing PBKDF2/TOTP, cite RFC 8018/RFC 6238.
- Keep a "threats to validity" paragraph in chapter 6: single environment,
  synthetic attacker fixtures, self-signed TLS, small negative-class size,
  and the detection-bound ingest throughput.
- Use a reference manager (Zotero/Mendeley/EndNote) from day one and enter
  every source as you read it.
