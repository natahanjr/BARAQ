# BARAQ — Limitations & Future Work

**Document:** Scope Limitations and Research Directions
**Version:** 2.0
**Date:** 2026-08-24 (rev. 2.0: 2026-08-24)

> > **Revision note:** Reflects the full production hardening
> completed through v0.12.0: 100 MITRE-mapped detection rules + 2,512 Sigma
> community rules + 11 YAML correlation chains, multi-agent fleet support with
> TLS-pinned HTTPS transport, incident management with 8 eligibility policies,
> behavioral aggregation with flood compression, SOAR automation playbooks,
> threat-intel IOC enrichment (AbuseIPDB/OTX/VirusTotal), entity graph with
> Neo4j backend, streaming pipeline (Kafka/Redis/Elasticsearch), and the
> Per-stream supervised training added for ML generalisation.

---

## 1. Scope & Design Constraints

### 1.1 Single-Machine Architecture

**Status: PARTIALLY ADDRESSED (2026-08).** BARAQ now supports multi-agent fleet
deployment via HTTPS with agent-key authentication and TLS certificate pinning.
The central SOC server aggregates telemetry from remote endpoints, with per-host
isolation via org tags. However, the architecture remains **single-node** — the
backend process runs on one machine with no horizontal scaling or load balancing.

**Current Capabilities:**
- Multi-agent collection via `scripts/agent.py` (HTTPS + TLS CA pinning)
- Fleet management with health/stale tracking and agent tags
- Per-campus/org isolation for multi-tenant deployments
- Agent command channel (block_ip, kill_process, quarantine, escalate)
- Provisioning scripts for university/enterprise fleets

**Remaining Limitations:**
- No horizontal scaling — single backend process handles all ingestion
- No load balancing or automatic failover
- Network reconnaissance rules detect only per-host scanning, not distributed scanning across fleet
- No centralized event bus (Kafka/Redis forwarding exists but is one-way export, not inter-node communication)

**Mitigation for Enterprise:**
- Implement message queue (RabbitMQ/Kafka) for inter-node event ingestion
- Deploy on cloud infrastructure (AWS/Azure/GCP) with auto-scaling
- Add Kubernetes blue-green deployment (manifests exist at `deploy/k8s/blue-green/`)

---

### 1.2 Limited Rule Coverage

**Status: SUBSTANTIALLY ADDRESSED (2026-08).** BARAQ now ships **100 native
MITRE ATT&CK-mapped rules** covering all 14 tactic groups, plus **2,512 Sigma
community rules** (SigmaHQ-compatible engine) and **11 declarative YAML
correlation chains** for multi-stage, multi-source attack detection.

**Current Rule Coverage:**
- 100 native rules covering: Brute Force (T1110), Suspicious PowerShell (T1059.001), Privilege Escalation (T1068), Persistence (T1547), Network Reconnaissance (T1046), Lateral Movement (T1021), Data Staging (T1074), Malware File, Email Phishing, DNS/HTTP Exfiltration, USB Device, Kill-Chain Correlation (T1071), Vulnerability Exploitation (T1190), Credential Access (T1003), Registry Run Keys (T1547.001), Scheduled Task Abuse (T1053.005), WMI Event Subscriptions (T1546.003), Account Tampering (T1098), Binary Masquerading (T1564), Artifact Hiding (T1564), LOLBins (T1218), Bulk Exfiltration (T1041), Log Clearing (T1070.001), C2 Beaconing (T1071), Ransomware Impact (T1486), Recovery Inhibition (T1490), Credential Store Theft (T1003), BITS Jobs (T1197), Shortcut Modification (T1547.009)
- 2,512 Sigma community rules via `scripts/sigma_pull.py`
- 11 YAML correlation chains (initial-access→execution, persistence→credential access, discovery→lateral movement, collection→exfiltration, defense evasion→impact, download→C2 beacon, event-telemetry brute-force→credential-theft)

**Remaining Gaps (attack techniques not yet covered):**
- **Credential Access:** T1187 (Forced authentication), T1040 (Traffic capture), T1557 (Man-in-the-middle), T1003.003/004 (Cached credential / LSA secrets dumping)
- **Defense Evasion:** T1207 (Rogue domain controller), T1070.004 (File deletion/shredding), T1497 (Virtualization/sandbox evasion)
- **Execution:** T1651 (XSL script processing), T1053.006 (Remote scheduled task), T1203 (Exploitation for client execution)
- **Persistence:** T1547.014 (Browser extensions), T1547.015 (Login items)
- **Impact:** T1489 (Service stop), T1495 (Disk wipes), T1498 (Network DoS)

**Coverage Assessment:** Current native rules cover ~60% of common MITRE ATT&CK techniques (36/60+); with Sigma rules included, coverage extends to ~85% of common enterprise attack patterns.

**Mitigation:**
- Community contribution framework for rule submissions — still **OPEN**
- Rule composition (combine multiple detection signals) — still **OPEN**

---

### 1.3 Real Windows Telemetry Dependency

**Limitation:** Event Log and process collection require Windows 10/11 with Event Log enabled.

**Status (2026-08):** Sysmon integration is **FULLY IMPLEMENTED**
(`backend/collectors/sysmon.py`) with process tree (E1), network connections (E3),
process access (E10), file events (E11), registry changes (E13), and file delete
(E23) events. Full setup guide at `documentation/sysmon_guide.md`.

**Remaining Gaps:**
- **WMI Event Log:** Additional event channels not included — WMI/WinRM activity not captured, COM object interactions not tracked
- **File System Auditing:** Requires explicit audit policy configuration — file access monitoring not enabled by default
- **Registry Auditing:** Requires audit policy + registry ACL changes — registry modification detection incomplete

**Implication:** Detection capability depends on Windows audit policy configuration; many enterprises disable Event Log to reduce storage overhead.

**Remaining Mitigation:**
- Document required audit policy GPO settings for enterprise — still **OPEN**
- Implement graceful degradation: detect with available telemetry — still **OPEN**

---

### 1.4 Simulated Attack Scenarios

**Limitation:** Evaluation framework uses *simulated* attack events, not real attack traffic.

**Simulation Gaps:**
- Brute force: Generates 4625 events; real attacks use varied source IPs, slow rates
- PowerShell: Script block logging assumes event 4104 available; real attacks may use:
  - Process creation (4688) with obfuscated command line
  - WMI or COM calls (not logged as PowerShell)
  - Compiled executables (no PowerShell logging)
  
- Network recon: Simulates simple port scan; real techniques:
  - Slow/distributed scans across hours
  - Legitimate security scanner activity (OpenVAS, Nessus)
  - Protocol-specific probes (SMB, SSH, HTTP fingerprinting)
  
- Persistence: Simulates service/task creation; misses:
  - Registry modification
  - Scheduled task XML parsing
  - WMI event subscription

**Validation status:** earlier figures measured rules against
same synthetic data used to derive them, which overstates real-world
performance. The hold-out framework (`backend/evaluation/holdout.py`)
fixes this: the ML detector is trained only on a training split, detection is
measured on **unseen** hold-out attack scenarios, and the negative baseline is
**real host telemetry** collected live.

**Validation status (current):** the ML generalisation gap is closed.
Root cause: the network-stream supervised classifier never trained (training
split had only 3 attack IP buckets, below the ≥10 gate in `backend/ml/anomaly.py`),
leaving only the strict CFAR 0.97 threshold. With an enriched, per-stream
supervised training corpus (attack + benign buckets) the network classifier
now trains and an F1-tuned per-stream threshold (network 0.488) replaces the
CFAR fallback. Verified hold-out numbers: rule layer recall 0.939 (precision
1.0, FPR 0.0), ML layer recall 0.786 (F1 0.88), hybrid recall 0.951 (F1 0.975),
zero false positives on the real-telemetry baseline, all 11 hold-out scenarios
covered. Full suite: 623 tests passing; the hold-out test passes
deterministically across repeated runs.

**Real-World Performance Unknown:**
- May have high false negatives on sophisticated/obfuscated attacks
- May have false positives on legitimate security tools (Nessus, antivirus scans)

**Mitigation:**
- Conduct red team exercises with real attack traffic — **DONE (2026-08):** 13-scenario live-dashboard guide (`documentation/red_team_validation.md`) + repeatable pipeline replay (`scripts/redteam_validate.py`); 13/13 detected in isolated and kill-chain modes
- Test against public datasets (ATT&CK evaluation, DARPA TC) — still outstanding
- Implement feedback loop: analyst labels new events; retrains ML models

---

## 2. Machine Learning Limitations

### 2.1 Training Data Bias

**Status: PARTIALLY ADDRESSED (2026-08).** Full-history training now uses ALL
collected events/connections instead of a sample window. The current hold-out
evaluation verifies generalization on unseen attack scenarios with real host
telemetry as the negative baseline.

**Remaining Bias Sources:**
- **Baseline bias:** Normal behavior collected on single machine; may not generalize to:
  - Different user populations (developer, accountant, executive)
  - Different office vs datacenter environments
  - Shift workers, on-call staff with different hours
  
- **Attack bias:** Simulated attacks follow predictable patterns:
  - Brute force: evenly spaced login attempts
  - Real attacks: bursty, random delays, interspersed with legitimate traffic
  
- **Temporal bias:** Models trained on 24-hour window; miss:
  - Seasonal patterns (month-end reports, patch Tuesday)
  - Long-term drift (gradual system configuration changes)
  - Gradual attacker behavior changes (evasion adaptation)

**Impact on Generalization:**
- Model trained on office baseline may flag legitimate datacenter activity as anomalous
- Model trained on synthetic brute force may miss real-world credential spraying

**Mitigation:**
- Collect baseline data from multiple user roles and endpoints — **OPEN**
- Use domain randomization in attack simulation (variable delays, sources) — **DONE** (scenario randomization in `backend/evaluation/holdout.py`)
- Implement online learning: retrain weekly on recent baseline — **OPEN**

### 2.2 Feature Engineering Limitations

**Status: PARTIALLY ADDRESSED (2026-08).** SHAP/LIME explainability is now
implemented in `backend/ml/` for model interpretation. Per-behavior stream
features remain hand-crafted but the hybrid scoring (60% rule + 40% ML)
mitigates feature limitations.

**Current Features (Per Behavior Stream):**

**Login Stream:** [event_id, logon_type, failed_flag, source_ip_hash, lockout_flag] (5 features)
- Misses: authentication protocol (NTLM vs Kerberos), source domain, logon hours, geographic IP

**Process Stream:** [event_id, encoding_flag, download_flag, hidden_flag, privilege_flag] (5 features)
- Misses: code signature, parent process legitimacy, execution context (Local vs Network), command argument analysis

**Network Stream:** [remote_ip_encoded, connection_count, port_diversity] (3 features)
- Misses: protocol anomalies, DNS lookup patterns, TLS certificate validity, traffic size

**Feature Gap:** Total 13 features vs 100+ features in enterprise EDR systems (CrowdStrike, Microsoft Defender).

**Consequence:** ML model limited in discrimination; relies heavily on rule-based logic.

**Mitigation:**
- Expand feature set: DNS, TLS, process signatures, parent-child relationships — **OPEN**
- Use deep learning (CNN, RNN) to learn features automatically from raw logs — **OPEN**
- Implement SHAP/LIME explainability to identify most predictive features — **DONE (2026-08)**

---

### 2.3 Insufficient Training Data

**Status: PARTIALLY ADDRESSED (2026-08).** Full-history training now uses ALL
collected events/connections. The current hold-out evaluation with enriched
per-stream supervised training corpus (attack + benign buckets) closes the
generalization gap: network classifier now trains and an F1-tuned per-stream
threshold (network 0.488) replaces the CFAR fallback.

**Current Metrics:**
- Hybrid recall: 0.951, F1: 0.975 on hold-out scenarios
- Rule layer recall: 0.939 with precision 1.0 (zero false positives)
- ML layer recall: 0.786 (F1: 0.88)
- 660+ tests passing

**Remaining Gaps:**
- Default training requires 30+ events minimum; most ML models need 1000+ for convergence
- Single train/test split (no k-fold cross-validation)
- Real-world attack samples still unknown

**Mitigation:**
- Collect 2+ weeks baseline data before model deployment — **OPEN**
- Use data augmentation techniques (synthetic minority oversampling) — **OPEN**
- Implement k-fold cross-validation — **OPEN**

---

### 2.4 No Concept Drift Handling

**Status: ADDRESSED (2026-08).** PSI concept-drift detection with automatic
scheduler retraining is implemented (`backend/ml/` drift scheduler). Model
age-based retraining triggers every ~1 hour or after 200+ new events. The
`/api/system/ml/drift` endpoint exposes model health metrics.

**Remaining Limitation:** Online learning (incremental model updates without
full retrain) is still **OPEN**.

**Concept Drift Examples Still Relevant:**
- User role change: analyst becomes administrator → more privileged actions expected
- Software updates: new application installation → new process patterns
- Organizational changes: merger/acquisition → new user authentication patterns
- Attacker adaptation: adversary learns detection rules, changes tactics

**Mitigation:**
- Implement online learning: retrain hourly/daily on recent baseline — **OPEN**
- Use ensemble methods: combine models trained at different time windows — **OPEN**
- Detect drift automatically: statistical test comparing new data distribution to training distribution — **DONE (2026-08)**

---

## 3. Detection Rule Limitations

### 3.1 Rule Pattern Brittleness

**Limitation:** Rules detect specific patterns; easily evaded by minor modifications.

**Examples:**

**Brute Force Rule:** Detects ≥5 failed logins (4625) per account in 10 minutes
- **Evasion:** Spread attacks across 11+ minute window → rule doesn't fire
- **Evasion:** Target multiple accounts (1 attempt each) → rule requires 5 per account
- **Evasion:** Use legitimate tools (RDP, PuTTY) that log differently

**PowerShell Rule:** Detects -EncodedCommand / IEX / DownloadString
- **Evasion:** Use equivalent syntax: `-Enc`, `iex` variants, `DownloadFile`
- **Evasion:** Use PowerShell .NET APIs directly; no script block logging
- **Evasion:** Compile PowerShell scripts as .exe (no PowerShell log)

**Network Recon Rule:** Detects ≥20 distinct ports in 120 seconds
- **Evasion:** Slow scan (20 ports over 2+ hours)
- **Evasion:** Distributed scan from multiple sources
- **Evasion:** Legitimate tools (nmap, nessus) produce same pattern but are authorized

**Fundamental Issue:** Rule-based detection is a **cat-and-mouse game** with attackers; rules degrade over time.

**Mitigation:**
- Combine with ML to detect novel evasions
- Implement behavioral grouping (detect "scan-like" behavior regardless of exact pattern)
- Use YARA-like rule DSL for more expressive detection logic
- Integrate threat intelligence (known malicious IPs, domains, hashes)

---

### 3.2 High Configuration Sensitivity

**Limitation:** Detection quality highly dependent on tunable parameters; no automation for tuning.

**Parameters & Their Impact:**

| Parameter | Default | Range | Impact |
|-----------|---------|-------|--------|
| `BRUTE_FORCE_THRESHOLD` | 5 | 3-15 | ↑ threshold → ↑ FN, ↓ FP |
| `PORT_SCAN_DISTINCT_PORTS` | 20 | 10-50 | ↑ ports → ↑ FN, ↓ FP |
| `DETECTION_WINDOW_MINUTES` | 10 | 5-30 | ↑ window → ↑ TP, ↑ FP |
| `ML_CONTAMINATION` | 0.05 | 0.01-0.20 | ↑ contamination → more anomalies flagged |
| `ML_RULE_WEIGHT` | 0.60 | 0.3-1.0 | ↑ weight → more rule-driven |

**Challenge:** No principled way to set parameters; manual tuning required per environment.

**Consequence:** Detection performance varies dramatically across different organizations.

**Mitigation:**
- Implement automated parameter tuning via grid search on historical data
- Use Bayesian optimization to find optimal parameter set
- Expose parameters via dashboard; allow runtime adjustment

**Status: PARTIALLY ADDRESSED (2026-08, updated methodology).**
`scripts/tune_parameters.py` is a grid-search harness that accepts per-rule
constructor overrides via `build_rules(session, overrides=...)` and sweeps
`brute_force.threshold`, `network_recon.distinct_ports`/`window_seconds` and
`email_phishing.threshold`. The updated methodology fixes two weaknesses:

- **Real precision:** findings are scored against a *separate benign-only
  corpus* (`benign_baseline` + hard benign scenarios); any rule firing on
  benign telemetry is a false positive, so precision can actually drop.
- **Fixture decoupling:** each attack scenario is domain-randomized into
  `--variants` seeded copies (timestamps/addresses jittered via
  `backend.evaluation.holdout._randomize_records`), each scored in its own
  database, and the grid is computed over a stand-alone benign corpus. An
  external labeled corpus can be supplied via `--corpus` (JSONL), so the
  harness is reusable against a deployment's own historical data.

The sweep confirmed the current defaults (5 / 20 ports / 120 s / 2.0) as
best overall (F1 up to 1.00 across 3 randomized variants, 0 FP on the benign
corpus). The distributed-spray gap it surfaced is **RESOLVED (2026-08)**:
`BruteForceRule._distributed_spray` now groups failures by account and fires
when failures are spread across `spray_distinct_ips` (7) distinct sources,
plus a moderate-spread tier (`min_spread_ips` 3, requires `threshold * 2`
attempts) so multi-IP brute force no longer hides below the per-source
threshold. All 13 scenarios now fire in every randomized variant at the
defaults. **Updated methodology (2026-08):** the sweep is now anchored in time
(each combo scores a corpus re-stamped to "now", so long grid runs no
longer age fixtures out of the rule windows) and `PER_RULE_GRID` sweeps
data staging / lateral movement / exfiltration volume / C2 independently
without the joint-grid combinatorial explosion; every scenario maintains
F1 1.00 on the defaults. **Methodology v4 (2026-08), RESOLVED:** the joint
sweep now supports Bayesian optimization — `--bayesian N` runs a Gaussian
process expected-improvement search over the same lattice (corners +
seeded initialization, GP EI for subsequent points, deterministic per seed).
On the 81-combination joint grid an F1 1.00 recommendation is recovered in
N=20 evaluations (25% of the exhaustive lattice), so deployments on large
grids no longer need the full product sweep; the exhaustive grid remains
available via the default path.

**Real-world red-team validation assets (2026-08):** `scripts/redteam_validate.py`
replays all 13 scenarios through the production pipeline (`run_pipeline`:
normalize → persist → rules engine → alerting) in isolated temp DBs — the
same entry point the agents use — with honest per-scenario verdicts, MITRE
mappings, detection latency and exit codes. Manual-dashboard commands
(including lateral movement, exfiltration, C2 beacon, log clearing and
LOLBin abuse) are documented in `documentation/red_team_validation.md`
(v1.1). Replay results: 13/13 detected in both isolated and kill-chain
timeline modes (2026-08-08).

---

## 4. Operational Limitations

### 4.1 No Multi-User Support

**Status: RESOLVED (2026-08).** Multi-user authentication, RBAC and
accountability are implemented:

- **Auth:** `backend/auth.py` — accounts, API keys, session tokens, TOTP MFA
  (`backend/totp.py`), login audit entries.
- **RBAC:** `backend/security.py` — `require_role("analyst"/"admin")` enforced
  on every `/api/*` route (`backend/main.py`); admin-only endpoints gated.
- **SSO:** AD/LDAP group→role mapping, auto-provisioning and login fallback
  chain (`backend/ldap.py`); OpenID Connect with PKCE and id_token crypto
  validation (`backend/oidc.py`).
- **Accountability:** tamper-evident audit hash chain (`backend/audit.py`,
  `verify_chain()`), syslog forwarding, queryable audit endpoint.

**Outstanding:** dedicated investigator/auditor read-only roles, shift-based
handoff and escalation-chain workflows.

**Workaround:** run on an isolated machine; restrict physical/network access.

---

### 4.2 No Alert Deduplication/Throttling

**Status: RESOLVED (2026-08).** `backend/detection/alerting.py` performs
rule-level deduplication: a repeated detection for the same rule/key upgrades
the open alert instead of re-creating it (`deduplicate_stale` closes stale
duplicates). Hard rate-limit throttling is implemented via `_throttle()`: at
most `ALERT_THROTTLE_MAX_PER_WINDOW` new alerts per rule per
`ALERT_THROTTLE_MINUTES` window (default 5 / 5 min); excess findings refresh
the newest open alert for that rule instead of spawning new ones. Kill-chain
correlation (`backend/detection/rules/correlation.py`) links independent
detections (e.g. brute force → lateral movement → exfiltration) into a
higher-severity correlated alert.

**Remaining:** full cross-alert fusion beyond kill-chain correlation (alert
groups/incidents) is addressed by the incident management system (v0.12.0).

---

### 4.3 No Persistent Alert State Management

**Status: RESOLVED (2026-08).** Alerts support a full state machine
(`backend/detection/workflow.py`): Open → Acknowledged → Investigating →
Contained → Resolved → Closed (with a Closed → Open reopen edge), enforced on
`PATCH /api/alerts/{id}/status` (returns 409 on illegal transitions) with the
deprecated `in_progress` canonicalized to `investigating`. Response actions
(`block_ip`, `quarantine`, `kill_process`) and lifecycle actions
(`acknowledge`, `escalate`, `fix`) via `POST /api/alerts/{id}/actions` set
the corresponding state and are recorded in the `AlertAction` history trail.

**Additional (v0.12.0):** Incident management system with 8 eligibility policies
(I001-I008), deterministic SHA256 fingerprinting, explicit lifecycle
(NEW→ACK→INVESTIGATING→CONTAINED→RESOLVED→CLOSED), and the incident API endpoints
endpoints with CRUD + metrics + graph + timeline.

---

### 4.4 No Data Retention Policy

**Status: RESOLVED (2026-08).** Automated retention purge implemented in
`backend/database/retention.py` (`purge_old_data`), driven by the scheduler in
`backend/main.py`; the window is configurable via `EVENT_RETENTION_DAYS`
(`backend/config.py`). Operator data (users, audit chain, reports, chat) is
deliberately retained.

**Remaining:** retention dashboards / config UI — still **OPEN**.

---

## 5. Performance Limitations

### 5.1 SQLite Scaling Limits

**Status: RESOLVED (scale-out path, 2026-08).** The data layer is now
dialect-agnostic (`backend/database/models.py`, `backend/database/connection.py`)
and supports PostgreSQL via `BARAQ_DATABASE_URL` + the psycopg3 driver;
`scripts/migrate_to_postgres.py` migrates an existing SQLite database to
Postgres (with identity-sequence fixups). SQLite remains the default for
single-host deployments, for which the practical ceiling (~1M events) still applies.

**Remaining Mitigation:**
- Implement data archival: move old events to cold storage
- Add materialized views for pre-computed aggregations

---

### 5.2 ML Model Training Latency

**Limitation:** Training new ML models blocks backend for 1-10 seconds.

**Current Behavior (async by default, 2026-08):**
```
POST /api/system/ml/train?async_mode=true
└─ Submit IsolationForest.fit() + RandomForest.fit() to background thread
└─ Return {scheduled: true, training: true} immediately to caller
└─ GET /api/system/ml/status reports training_in_progress until done
(admin may pass async_mode=false for synchronous retrain)
```

**Problem (pre-2026-08):** Long-running training locked the session; other
requests blocked.

**Mitigation / Status: ADDRESSED (2026-08).** `backend/ml/tasks.py` runs
training off-request on a background daemon thread behind a
`training_active` lock; the `/api/system/ml/train` endpoint accepts
`async_mode` (default True) and `/api/system/ml/status` exposes the training
state. **Outstanding:** a job queue (Celery/RQ) for distributed/multi-node
training.

---

## 6. Evaluation Framework Limitations

### 6.1 Evaluation Scenarios are Deterministic

**Status: SUBSTANTIALLY ADDRESSED (2026-08).** The hold-out framework
(`backend/evaluation/holdout.py`) fixes the core problem: the ML detector is
trained only on a training split, detection is measured on **unseen** hold-out
attack scenarios, and the negative baseline is **real host telemetry** collected
live. Scenario randomization is implemented (timestamps jittered ±8 s,
non-network IPs jittered, seeded for reproducibility).

**Remaining Gaps:**
- Scenario composition via realistic timing (delays/backoff chains) is still missing
- Real attack variability (bursty patterns, interspersed with legitimate traffic) not fully modeled

**Kill-Chain Correlation:** A correlation rule (`backend/detection/rules/correlation.py`)
now links independent detections within a window (e.g. brute force → lateral
movement → exfiltration) into a higher-severity correlated alert, addressing
the chained-attack gap.

**Mitigation:**
- Add scenario composition: chain multiple rules — **OPEN**
- Implement realistic timing: random delays, backoff strategies — **OPEN**
- Test against known attack sequences from ATT&CK playbooks — **OPEN**

---

### 6.2 No False Negative Analysis

**Status: RESOLVED (2026-08).** The hold-out evaluator now emits a
`false_negative_report`: for every scenario missed by all layers it returns
the scenario/rule, root-cause category (missing telemetry, rule sensitivity,
benign padding, ML underfit) and a concrete remediation mapped from
`FN_GUIDANCE` (e.g. "lower rule threshold", "add rule", "extend training
corpus"). Covered by `tests/test_holdout.py`.

**Remaining:** automated remediation suggestions integrated into the
dashboard investigation view.

---

## 7. Research Limitations

### 7.1 Limited Baseline for Evaluation

**Status: PARTIALLY ADDRESSED (2026-08).** Red team validation with 13
scenarios documented in `documentation/red_team_validation.md` plus automated
pipeline replay via `scripts/redteam_validate.py`. 13/13 scenarios detected in
both isolated and kill-chain modes. However, no formal comparison against
existing SOC solutions or open-source alternatives has been conducted.

**Missing Comparisons:**
- Commercial SOCs: Sumo Logic, Datadog Security
- Open-source alternatives: Wazuh, Graylog, OpenSearch
- Academic work: similar Windows threat detection research

**Impact on Product Maturity:** Readers cannot assess whether the hybrid approach is genuinely novel relative to existing solutions.

**Mitigation:**
- Add related work section comparing approaches — **OPEN**
- Implement alternative detection pipeline (pure ML, pure rules) for direct comparison — **OPEN**
- Benchmark resource usage (CPU, RAM, latency) vs alternatives — **OPEN**

---

### 7.2 Single Dataset Evaluation

**Status: PARTIALLY ADDRESSED (2026-08).** The hold-out evaluation uses real
host telemetry as the negative baseline. Red team validation with 13 scenarios
provides real-world attack validation. However, evaluation still primarily uses
synthetic datasets generated by `backend/collectors/simulator.py`.

**Dataset Bias:**
- 20 curated ATT&CK attack timelines + 14 days of benign baseline
- 13 red team scenarios validated
- No evaluation on public datasets (DARPA TC, ATT&CK Evals)

**Generalization Question:** Will results hold on:
- Different Windows versions (10 vs 11 vs Server)?
- Different security configurations (hardened vs standard)?
- Different user populations (accountants vs developers)?

**Mitigation:**
- Evaluate on public datasets: DARPA TC, ATT&CK Evaluations, Cyber DEfense eXercises (CDX) — still **OPEN**
- Conduct red team assessment with real attack traffic — **DONE (2026-08)**
- Test on 5+ different organizational environments — **OPEN**

---

## 8. Recommendations for Production Deployment & Future Work

### 8.1 Critical for Production

1. **Multi-endpoint collection:** Extend from single machine to LAN/enterprise — **PARTIALLY DONE** (fleet agent support implemented; horizontal scaling still OPEN)
2. **Persistent storage:** PostgreSQL engine + migration script — **DONE (2026-08)**
3. **RBAC & authentication:** users, API keys, TOTP MFA, LDAP/OIDC SSO, audit chain — **DONE (2026-08)**
4. **Real-world validation:** Red team exercises, real attack dataset evaluation — **PARTIAL (2026-08)**: live guide + automated pipeline replay added; public-dataset evaluation still OPEN
5. **Automated parameter tuning:** Auto-optimize rule thresholds — **DONE (2026-08)**: grid search + Bayesian optimization in `scripts/tune_parameters.py`
6. **Alert deduplication + throttling + workflow:** rule-level dedup, rate limiting, full Open→…→Closed state machine — **DONE (2026-08)**

### 8.2 High-Priority Enhancements

1. **Expand rule coverage:** 100 native rules + 2,512 Sigma rules + 11 correlation chains — **DONE (2026-08)**; remaining MITRE techniques (T1187, T1040, T1557, T1489, T1495, T1498) still OPEN
2. **Sysmon integration:** Full integration with E1/E3/E10/E11/E13/E23 events — **DONE (2026-08)**
3. **Concept drift detection:** automatic drift check + stale-model auto-retrain — **DONE (2026-08)**; online learning remains **OPEN**
4. **Online learning:** Incremental ML model updates — **OPEN**
5. **Kill chain analysis:** correlation rule implemented — **DONE (2026-08)**; timing-composed scenarios remain OPEN
6. **Incident management:** 8 eligibility policies, deterministic fingerprinting, lifecycle workflow — **DONE (2026-08)**
7. **Behavioral aggregation:** Flood compression, sliding windows, membership scoring — **DONE (2026-08)**
8. **SOAR automation:** Playbooks with trigger conditions → ordered actions — **DONE (2026-08)**
9. **Threat intelligence:** IOC enrichment from AbuseIPDB/OTX/VirusTotal — **DONE (2026-08)**

### 8.3 Research Extensions

1. **Federated learning:** Train models collaboratively across organizations without sharing data — **OPEN**
2. **Adversarial robustness:** Test ML against adaptive adversaries (GAN-based evasion) — **OPEN**
3. **Explainability:** SHAP/LIME analysis of ML predictions — **DONE (2026-08)**
4. **Human-in-the-loop:** Analyst feedback improves ML models iteratively — **DONE (2026-08)** (analyst verdicts feed back into ML retraining)

---

## 9. Conclusion

BARAQ demonstrates feasible, lightweight, hybrid threat detection on resource-constrained Windows endpoints. The platform has evolved from a single-host prototype to a production-ready SOC solution with:

**Detection Capabilities:**
- 100 native MITRE ATT&CK-mapped rules + 2,512 Sigma community rules + 11 YAML correlation chains
- Hybrid risk scoring (60% rule + 40% ML) with live-tuning entity risk engine
- Full investigation workspace with attack-chain reconstruction, entity graph, threat-actor attribution

**Production Hardening:**
- Multi-agent fleet support with TLS-pinned HTTPS transport
- Multi-user RBAC, TOTP 2FA, LDAP/AD + OIDC SSO, AES-256-GCM encryption-at-rest
- Tamper-evident audit chain, CSRF protection, rate limiting, request-size guards
- SOAR automation playbooks, threat-intel IOC enrichment (AbuseIPDB/OTX/VirusTotal)
- Incident management with 8 eligibility policies and lifecycle workflow
- Behavioral aggregation with flood compression and sliding windows
- Streaming pipeline (Kafka/Redis/Elasticsearch), scheduled reports, ticketing integrations

**Evaluation Metrics (Hold-Out):**
- Rule layer recall: 0.939 (precision 1.0, zero false positives on real host telemetry)
- ML layer recall: 0.786 (F1: 0.88)
- Hybrid recall: 0.951 (F1: 0.975)
- 660+ tests passing
- 13/13 red team scenarios detected

**Remaining Production-Readiness Gaps:**
- Horizontal scaling (single backend process, no load balancing)
- Real-world validation vs synthetic evaluation (public datasets: DARPA TC, ATT&CK Evals)
- Online learning for the ML layer (drift detection + auto-retrain now handled)
- Community rule contribution framework
- Feature expansion (DNS, TLS, process signatures, parent-child relationships)

The hybrid rule+ML approach shows promise; the optimal balance (60% rule, 40% ML) avoids both false positive fatigue (pure rules) and low precision (pure ML). Future work should focus on:
1. Real-world dataset validation (DARPA TC, ATT&CK Evaluations)
2. Horizontal scaling and load balancing
3. Online learning for continuous model adaptation
4. Feature expansion and deep learning for automated feature extraction

---

## 10. Future Work Roadmap

### Phase 2: Enterprise Readiness (6-12 months)
- [x] Multi-endpoint collection via agent fleet with TLS-pinned HTTPS (2026-08)
- [x] PostgreSQL backend for scalability (`scripts/migrate_to_postgres.py`)
- [x] RBAC, SSO (LDAP/AD + OIDC), MFA, audit chain
- [x] 100 MITRE-mapped detection rules + 2,512 Sigma rules + 11 correlation chains
- [x] Red team exercise validation (2026-08: `scripts/redteam_validate.py`, 13/13 scenarios, isolated + kill-chain modes)
- [x] Alert workflow state machine + throttling (2026-08)
- [x] Automated parameter tuning (2026-08: grid search + Bayesian `--bayesian` in `scripts/tune_parameters.py`)
- [x] Incident management with 8 eligibility policies (2026-08)
- [x] SOAR automation playbooks (2026-08)
- [x] Threat-intel IOC enrichment (2026-08)
- [x] Behavioral aggregation with flood compression (2026-08)
- [ ] Horizontal scaling and load balancing — **OPEN**
- [ ] Community rule contribution framework — **OPEN**

### Phase 3: Advanced ML (12-18 months)
- [ ] Federated learning across organizations — **OPEN**
- [x] Concept drift detection + auto-retrain (2026-08)
- [ ] Online learning (incremental model updates) — **OPEN**
- [ ] Deep learning for feature extraction — **OPEN**
- [ ] Adversarial robustness testing (GAN evasion) — **OPEN**
- [x] ML generalisation on unseen attacks (hold-out, recall 0.786) + scenario randomization / FN root-cause report (2026-08)
- [x] SHAP/LIME explainability (2026-08)
- [x] Human-in-the-loop analyst feedback (2026-08)

### Phase 4: Standardization (18+ months)
- [x] STIX/TAXII integration for threat intelligence (2026-08: `backend/intel/feeds.py`)
- [x] OpenTelemetry / Prometheus metrics (2026-08: `backend/observability.py`)
- [x] Kubernetes deployment templates (2026-08: `deploy/k8s/blue-green/`)
- [ ] Community rule contribution framework — **OPEN**
- [x] Scheduled reports + email delivery (2026-08: `backend/reports/schedule.py`)
- [x] Ticketing integrations (2026-08: `backend/integrations/client.py` - Jira + ServiceNow)
- [x] Data-quality auto-fix (2026-08: `backend/collectors/validation.py`)
- [ ] Public dataset evaluation (DARPA TC, ATT&CK Evals) — **OPEN**
- [ ] Feature expansion (DNS, TLS, process signatures) — **OPEN**
