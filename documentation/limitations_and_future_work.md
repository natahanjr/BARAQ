# BARAQ — Limitations & Future Work

**Document:** Scope Limitations and Research Directions
**Version:** 1.1
**Date:** 2026-08-06 (rev. 1.0: 2026-08-04)

> **Revision note (v1.1):** sections marked **RESOLVED** / **PARTIALLY ADDRESSED**
> reflect hardening completed since v1.0: multi-user auth + RBAC + MFA, LDAP/OIDC
> SSO, tamper-evident audit chain, encryption-at-rest, CSRF + request-size guards,
> retention purging, PostgreSQL scale-out, alert dedup / kill-chain correlation,
> Sysmon integration, and the v2 ML-generalisation fix.

---

## 1. Scope & Design Constraints

### 1.1 Single-Machine Architecture

**Limitation:** BARAQ is designed to run entirely on a single Windows 11 laptop with no external infrastructure.

**Implications:**
- No distributed collection from multiple endpoints
- No centralized aggregation or correlation across hosts
- No horizontal scaling for enterprise deployments
- Network reconnaissance rules detect only local port scanning, not distributed scanning

**Rationale:** lightweight deployment for single-host and small-fleet monitoring on resource-constrained hardware (i5, 12GB RAM, SSD).

**Mitigation for Enterprise:**
- Add multi-agent collection via WinRM or EDR plugin architecture
- Implement message queue (RabbitMQ/Kafka) for centralized event ingestion
- Deploy on cloud infrastructure (AWS/Azure/GCP) with auto-scaling

---

### 1.2 Limited Rule Coverage

**Limitation:** 29 detection rules implemented (7 core + lateral movement, data staging, malware file, email phishing, DNS/HTTP exfiltration, USB, C2 beaconing, kill-chain correlation, vulnerability scanning, plus the Tier 1 set: LSASS memory access T1003.001, registry run keys T1547.001, scheduled task abuse T1053.005, WMI event subscriptions T1546.003, account tampering T1098, binary masquerading T1036, artifact hiding T1564, system binary proxy/LOLBins T1218, bulk exfiltration T1041, event log clearing T1070.001, ransomware/impact T1486, recovery inhibition T1490, credential store theft T1555, BITS jobs T1197, shortcut modification T1547.009).

**Attack Techniques Not Covered:**
- **Credential Access (T1110 variants):** Covers brute force, LSASS dumping, and credential store theft; missing:
  - T1187: Forced authentication
  - T1040: Traffic capture
  - T1557: Man-in-the-middle
  - T1003.003/004: Cached credential / LSA secrets dumping

- **Defense Evasion (T1xxx):**
  - T1207: Rogue domain controller
  - T1070.004: File deletion / shredding
  - T1497: Virtualization/sandbox evasion

- **Execution (T1xxx):**
  - T1651: XSL script processing
  - T1053.006: Scheduled task creation on remote systems
  - T1203: Exploitation for client execution

- **Persistence (T1547 variants):**
  - T1547.014: Browser extensions
  - T1547.015: Login items

- **Impact:** T1489 (service stop), T1495 (disk wipes), T1498 (network DoS)

**Coverage Gap:** Current ruleset covers ~40% of common MITRE ATT&CK techniques (26/60+); the earlier ~15% figure referred to the 7-rule baseline. Threshold sensitivity is being addressed by `scripts/tune_parameters.py`, a grid-search harness that scores every parameter combination against the labelled attack corpus (current defaults — brute force threshold 5, port scan 20 ports/120 s, phishing score 2.0 — are confirmed optimal for the synthetic corpus, F1 = 1.0).

**Mitigation:**
- Add rule templates in `backend/detection/rules/` for each technique
- Community contribution framework for rule submissions
- Implement rule composition (combine multiple detection signals)

---

### 1.3 Real Windows Telemetry Dependency

**Limitation:** Event Log and process collection require Windows 10/11 with Event Log enabled.

**Missing Data Sources:**
- **Sysmon:** Advanced process tracking, network connections, registry changes
  - Requires sysmon driver installation + config
  - Not part of baseline Windows (third-party dependency)
  
- **WMI Event Log:** Additional event channels not included
  - WMI/WinRM activity not captured
  - COM object interactions not tracked
  
- **File System Auditing:** Requires explicit audit policy configuration
  - File access monitoring not enabled by default
  - Sensitive data exfiltration may not be detected
  
- **Registry Auditing:** Requires audit policy + registry ACL changes
  - Registry modification detection incomplete

**Implication:** Detection capability depends on Windows audit policy configuration; many enterprises disable Event Log to reduce storage overhead.

**Status (2026-08):** a Sysmon integration layer now exists at
`backend/collectors/sysmon.py`; WMI, filesystem and registry auditing remain
config-gated.

**Remaining Mitigation:**
- Document required audit policy GPO settings for enterprise
- Implement graceful degradation: detect with available telemetry

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

**Validation status (v2):** the v1 96.67% figure measured rules against the
same synthetic data used to derive them, which overstates real-world
performance. The v2 hold-out framework (`backend/evaluation/holdout.py`)
fixes this: the ML detector is trained only on a training split, detection is
measured on **unseen** hold-out attack scenarios, and the negative baseline is
**real host telemetry** collected live.

**Validation status (v2.1, 2026-08):** the ML generalisation gap is closed.
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

**Limitation:** ML models trained on simulated baseline + synthetic attacks, not real-world data.

**Bias Sources:**
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
- Collect baseline data from multiple user roles and endpoints
- Use domain randomization in attack simulation (variable delays, sources)
- Implement online learning: retrain weekly on recent baseline

### 2.2 Feature Engineering Limitations

**Limitation:** Hand-crafted features may miss subtle attack signals.

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
- Expand feature set: DNS, TLS, process signatures, parent-child relationships
- Use deep learning (CNN, RNN) to learn features automatically from raw logs
- Implement SHAP/LIME explainability to identify most predictive features

---

### 2.3 Insufficient Training Data

**Limitation:** Default training uses only 50-100 baseline events; most ML models need 1000+.

**Sample Size Analysis:**

| Data Requirement | Typical ML | BARAQ | Gap |
|------------------|-----------|------------|-----|
| Baseline events | 1,000+ | 50-100 | 10× |
| Attack samples | 500+ | Simulated | Real-world unknown |
| Feature count | 50-100 | 13 | 4-8× |
| Training/test split | 80/20 | 60/40 | Reduced test set |

**Impact:**
- Overfitting risk: model memorizes training data rather than learning patterns
- Underfitting risk: model too simple to capture real anomalies
- High variance: performance fluctuates across different baseline sets

**Mitigation:**
- Collect 2+ weeks baseline data before model deployment
- Use data augmentation techniques (synthetic minority oversampling)
- Implement k-fold cross-validation (currently: single train/test split)

---

### 2.4 No Concept Drift Handling

**Limitation:** ML models trained once; do not adapt to system changes.

**Concept Drift Examples:**
- User role change: analyst becomes administrator → more privileged actions expected
- Software updates: new application installation → new process patterns
- Organizational changes: merger/acquisition → new user authentication patterns
- Attacker adaptation: adversary learns detection rules, changes tactics

**Current Behavior:** Model trained on Day 1; used unchanged on Day 365.
- **False Positives increase:** New legitimate behaviors flagged as anomalous
- **False Negatives increase:** Attackers adapt; novel patterns not detected

**Mitigation:**
- Implement online learning: retrain hourly/daily on recent baseline
- Use ensemble methods: combine models trained at different time windows
- Detect drift automatically: statistical test comparing new data distribution to training distribution

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

**Status: PARTIALLY ADDRESSED (2026-08, methodology v2).**
`scripts/tune_parameters.py` is a grid-search harness that accepts per-rule
constructor overrides via `build_rules(session, overrides=...)` and sweeps
`brute_force.threshold`, `network_recon.distinct_ports`/`window_seconds` and
`email_phishing.threshold`. Methodology v2 fixes the two v1 weaknesses:

- **Real precision:** findings are scored against a *separate benign-only
  corpus* (`benign_baseline` + hard benign scenarios); any rule firing on
  benign telemetry is a false positive, so precision can actually drop.
- **Fixture decoupling:** each attack scenario is domain-randomized into
  `--variants` seeded copies (timestamps/addresses jittered via
  `backend.evaluation.holdout._randomize_records`), each scored in its own
  database, and the grid is computed over a stand-alone benign corpus. An
  external labeled corpus can be supplied via `--corpus` (JSONL), so the
  harness is reusable against a deployment's own historical data.

The v2 grid confirmed the current defaults (5 / 20 ports / 120 s / 2.0) as
best overall (F1 up to 1.00 across 3 randomized variants, 0 FP on the benign
corpus). The distributed-spray gap it surfaced is **RESOLVED (2026-08)**:
`BruteForceRule._distributed_spray` now groups failures by account and fires
when failures are spread across `spray_distinct_ips` (7) distinct sources,
plus a moderate-spread tier (`min_spread_ips` 3, requires `threshold * 2`
attempts) so multi-IP brute force no longer hides below the per-source
threshold. All 13 scenarios now fire in every randomized variant at the
defaults. **Methodology v3 (2026-08):** the sweep is now anchored in time
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

**Status: ADDRESSED (2026-08).** `backend/detection/alerting.py` performs
rule-level deduplication: a repeated detection for the same rule/key upgrades
the open alert instead of re-creating it (`deduplicate_stale` closes stale
duplicates). Hard rate-limit throttling is implemented via `_throttle()`: at
most `ALERT_THROTTLE_MAX_PER_WINDOW` new alerts per rule per
`ALERT_THROTTLE_MINUTES` window (default 5 / 5 min); excess findings refresh
the newest open alert for that rule instead of spawning new ones. Kill-chain
correlation (`backend/detection/rules/correlation.py`) links independent
detections (e.g. brute force → lateral movement → exfiltration) into a
higher-severity correlated alert.

**Outstanding:** full cross-alert fusion (alert groups/incidents).

---

### 4.3 No Persistent Alert State Management

**Status: ADDRESSED (2026-08).** Alerts support a full state machine
(`backend/detection/workflow.py`): Open → Acknowledged → Investigating →
Contained → Resolved → Closed (with a Closed → Open reopen edge), enforced on
`PATCH /api/alerts/{id}/status` (returns 409 on illegal transitions) with the
deprecated `in_progress` canonicalized to `investigating`. Response actions
(`block_ip`, `quarantine`, `kill_process`) and lifecycle actions
(`acknowledge`, `escalate`, `fix`) via `POST /api/alerts/{id}/actions` set
the corresponding state and are recorded in the `AlertAction` history trail.

**Outstanding:** escalation thresholding (auto-escalate N× unchanged alerts)
and cross-alert linking beyond the kill-chain correlation rule.

---

### 4.4 No Data Retention Policy

**Status: RESOLVED (2026-08).** Automated retention purge implemented in
`backend/database/retention.py` (`purge_old_data`), driven by the scheduler in
`backend/main.py`; the window is configurable via `EVENT_RETENTION_DAYS`
(`backend/config.py`). Operator data (users, audit chain, reports, chat) is
deliberately retained.

**Remaining:** retention dashboards / config UI.

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

**Limitation:** Simulated attacks follow predictable, optimal patterns.

**Real Attack Variability:**
- Adversary may retry after failed attempt (not deterministic)
- May use reconnaissance before attack (adds noise)
- May intersperse attack with legitimate traffic
- May coordinate across multiple techniques (kill chain simulation missing)

**Evaluation Gap:** Framework tests 5 attacks in isolation; real attacks **chain techniques**:
```
Recon → Brute Force → Lateral Movement → Persistence → Data Staging → Exfiltration
```

**Status (2026-08):** a kill-chain correlation rule
(`backend/detection/rules/correlation.py`) now links independent detections
within a window (e.g. brute force → lateral movement → exfiltration) into a
higher-severity correlated alert. Scenario randomization is implemented in
`backend/evaluation/holdout.py` (`run_holdout_evaluation(randomize=True,
seed=...)`): timestamps are jittered ±8 s (kept inside the port-scan window),
non-network IPs are jittered, and the randomization is seeded for
reproducibility — `POST /api/evaluation/holdout` accepts `randomize`/`seed`
and the report records the randomization method. Scenario composition via
realistic timing (delays/backoff chains) is still missing.

**Mitigation:**
- Add scenario composition: chain multiple rules
- Implement realistic timing: random delays, backoff strategies
- Test against known attack sequences from ATT&CK playbooks

---

### 6.2 No False Negative Analysis

**Limitation:** Framework reports FN count but not analysis of *why* detection failed.

**Current Output:**
```
False Negatives: 3
├─ 2 in Brute Force (benign scenario padding)
└─ 1 in Privilege Escalation (non-essential chain event)
```

**Missing Analysis:**
- Which specific events were missed?
- What features would have detected them?
- Is FN acceptable (benign padding) or critical (real attack)?
- How to fix: adjust threshold, add rule, retrain ML?

**Status: ADDRESSED (2026-08).** The hold-out evaluator now emits a
`false_negative_report`: for every scenario missed by all layers it returns
the scenario/rule, root-cause category (missing telemetry, rule sensitivity,
benign padding, ML underfit) and a concrete remediation mapped from
`FN_GUIDANCE` (e.g. "lower rule threshold", "add rule", "extend training
corpus"). Covered by `tests/test_holdout.py`.

---

## 7. Research Limitations

### 7.1 Limited Baseline for Evaluation

**Limitation:** No comparison against existing SOC solutions or open-source alternatives.

**Missing Comparisons:**
- Commercial SOCs: Splunk, Sumo Logic, Datadog Security
- Open-source alternatives: Wazuh, Graylog, OpenSearch
- Academic work: similar Windows threat detection research

**Impact on Product Maturity:** Readers cannot assess whether the hybrid approach is genuinely novel relative to existing solutions.

**Mitigation:**
- Add related work section comparing approaches
- Implement alternative detection pipeline (pure ML, pure rules) for direct comparison
- Benchmark resource usage (CPU, RAM, latency) vs alternatives

---

### 7.2 Single Dataset Evaluation

**Limitation:** All evaluation uses single synthetic dataset generated by `backend/collectors/simulator.py`.

**Dataset Bias:**
- 50 attack + 40 baseline events; small sample
- Only 5 attack types tested
- No evaluation on real-world datasets (DARPA TC, ATT&CK Evals)

**Generalization Question:** Will results hold on:
- Different Windows versions (10 vs 11 vs Server)?
- Different security configurations (hardened vs standard)?
- Different user populations (accountants vs developers)?

**Mitigation:**
- Evaluate on public datasets: DARPA TC, ATT&CK Evaluations, Cyber DEfense eXercises (CDX) — still outstanding
- Conduct red team assessment with real attack traffic — **DONE (2026-08)**: guide + `scripts/redteam_validate.py`, 13/13 detected
- Test on 5+ different organizational environments

---

## 8. Recommendations for Production Deployment & Future Work

### 8.1 Critical for Production

1. **Multi-endpoint collection:** Extend from single machine to LAN/enterprise — **OPEN**
2. **Persistent storage:** PostgreSQL engine + migration script — **DONE (2026-08)**
3. **RBAC & authentication:** users, API keys, TOTP MFA, LDAP/OIDC SSO, audit chain — **DONE (2026-08)**
4. **Real-world validation:** Red team exercises, real attack dataset evaluation — **PARTIAL (2026-08)**: live guide + automated pipeline replay added (`scripts/redteam_validate.py`, 13/13 detected); public-dataset evaluation still OPEN
5. **Automated parameter tuning:** Auto-optimize rule thresholds — **PARTIAL** (grid-search harness + Bayesian optimization `--bayesian` in `scripts/tune_parameters.py` added 2026-08; run on real data required)
6. **Alert deduplication + throttling + workflow:** rule-level dedup, rate limiting, full Open→…→Closed state machine — **DONE (2026-08)**

### 8.2 High-Priority Enhancements

1. **Expand rule coverage:** Added T1555, T1486/T1490, T1197, T1547.009 (2026-08) — **DONE (2026-08)**; T1021 and further techniques remain
2. **Sysmon integration:** integration layer added — **DONE (2026-08)**; wiring/config docs remain — **DONE (2026-08)**: see `documentation/sysmon_guide.md` (install, minimal config, verification, troubleshooting)
3. **Concept drift detection:** automatic drift check + stale-model auto-retrain — **DONE (2026-08)** (`backend/mitigation/ML` drift scheduler; online learning remains **OPEN**)
4. **Online learning:** Incremental ML model updates — **OPEN**
5. **Kill chain analysis:** correlation rule implemented — **DONE (2026-08)**; timing-composed scenarios remain

### 8.3 Research Extensions

1. **Federated learning:** Train models collaboratively across organizations without sharing data
2. **Adversarial robustness:** Test ML against adaptive adversaries (GAN-based evasion)
3. **Explainability:** SHAP/LIME analysis of ML predictions
4. **Human-in-the-loop:** Analyst feedback improves ML models iteratively

---

## 9. Conclusion

BARAQ demonstrates feasible, lightweight, hybrid threat detection on resource-constrained Windows endpoints. On the v2 external-validity evaluation, the rule layer reaches recall 0.939 with precision 1.0 (zero false positives on real host telemetry), and — after the v2.1 per-stream supervised training fix — the ML layer reaches recall 0.786 and the combined hybrid layer 0.951 recall / 0.975 F1, demonstrating that the core architecture soundly generalises beyond the data used to build it.

Remaining production-readiness gaps:
- Scaling from 1 machine to enterprise (multi-endpoint collection)
- Real-world validation vs synthetic evaluation
- Operational maturity: alert retention/visualisation, escalation auto-thresholding
- Online learning for the ML layer (drift detection + auto-retrain now handled)

The hybrid rule+ML approach shows promise; the optimal balance (60% rule, 40% ML) avoids both false positive fatigue (pure rules) and low precision (pure ML). Future work should focus on:
1. Real-world dataset validation
2. Automated parameter tuning
3. Multi-endpoint architecture
4. Adversarial robustness testing

---

## 10. Future Work Roadmap

### Phase 2: Enterprise Readiness (6-12 months)
- [ ] Multi-endpoint collection via WinRM / EDR agents
- [x] PostgreSQL backend for scalability (`scripts/migrate_to_postgres.py`)
- [x] RBAC, SSO (LDAP/AD + OIDC), MFA, audit chain
- [x] 10+ additional detection rules (29 rules + kill-chain correlation)
- [x] Red team exercise validation (2026-08: `scripts/redteam_validate.py`, 13/13 scenarios, isolated + kill-chain modes; manual live guide in `documentation/red_team_validation.md`) — public-dataset evaluation (DARPA TC / ATT&CK Evals) remains
- [x] Alert workflow state machine + throttling (2026-08)
- [x] Automated parameter tuning (2026-08: grid search + Bayesian `--bayesian` in `scripts/tune_parameters.py`; re-run on real deployment data required)

### Phase 3: Advanced ML (12-18 months)
- [ ] Federated learning across organizations
- [x] Concept drift detection + auto-retrain (2026-08); online learning remains
- [ ] Deep learning for feature extraction
- [ ] Adversarial robustness testing (GAN evasion)
- [x] ML generalisation on unseen attacks (v2.1 hold-out, recall 0.786) + scenario randomization / FN root-cause report (2026-08)

### Phase 4: Standardization (18+ months)
- [x] STIX/TAXII integration for threat intelligence (2026-08: `backend/intel/feeds.py` - TAXII 2.1, STIX 2.1 bundles, MISP restSearch, plain/CSV lists; scheduler + Celery `baraq.intel_refresh`; see `documentation/threat_intel_feeds.md`)
- [x] OpenTelemetry / Prometheus metrics (2026-08: `backend/observability.py` - SLO gauges `baraq_slo_health`/`baraq_slo_target`, OTLP/HTTP exporter, Grafana dashboard `deploy/grafana/dashboards/baraq-slos.json`)
- [x] Kubernetes deployment templates (2026-08: `deploy/k8s/blue-green/baraq-blue-green.yaml` + `scripts/blue_green_switch.ps1`)
- [ ] Community rule contribution framework
- [x] Scheduled reports + email delivery (2026-08: `backend/reports/schedule.py` + report-schedules API in `backend/api/reports.py` + Celery `baraq.scheduled_report`)
- [x] Ticketing integrations (2026-08: `backend/integrations/client.py` - Jira REST v2 + ServiceNow table API with health tracking; `backend/integrations/sdk.py` - official Python SDK; see `documentation/integrations.md`)
- [x] Data-quality auto-fix (2026-08: `backend/collectors/validation.py` discards corrupted rendering-debris events before detection; `backend/collectors/quality.py` + `data_quality_snapshots` tracking; `backend/collectors/repair.py` auto-repair sequence; `backend/monitor/data_quality.py` background monitor; `/api/system/data-quality*` endpoints; see `documentation/data_quality.md`)
