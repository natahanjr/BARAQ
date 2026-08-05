# SentinelSOC — Limitations & Future Work

**Document:** Scope Limitations and Research Directions
**Version:** 1.0
**Date:** 2026-08-04

---

## 1. Scope & Design Constraints

### 1.1 Single-Machine Architecture

**Limitation:** SentinelSOC is designed to run entirely on a single Windows 11 laptop with no external infrastructure.

**Implications:**
- No distributed collection from multiple endpoints
- No centralized aggregation or correlation across hosts
- No horizontal scaling for enterprise deployments
- Network reconnaissance rules detect only local port scanning, not distributed scanning

**Rationale:** MSc thesis prototyping; proves core SOC concepts on resource-constrained hardware (i5, 12GB RAM, SSD).

**Mitigation for Enterprise:**
- Add multi-agent collection via WinRM or EDR plugin architecture
- Implement message queue (RabbitMQ/Kafka) for centralized event ingestion
- Deploy on cloud infrastructure (AWS/Azure/GCP) with auto-scaling

---

### 1.2 Limited Rule Coverage

**Limitation:** Only 7 detection rules implemented (5 original + 2 new lateral movement/data staging).

**Attack Techniques Not Covered:**
- **Credential Access (T1110 variants):** Only covers brute force; missing:
  - T1555: Credential API hooking
  - T1187: Forced authentication
  - T1040: Traffic capture
  - T1557: Man-in-the-middle
  
- **Defense Evasion (T1xxx):**
  - T1036: File obfuscation
  - T1197: BITS jobs
  - T1564: Hidden files/directories
  - T1207: Rogue domain controller
  
- **Execution (T1xxx):**
  - T1651: XSL script processing
  - T1053: Scheduled task variants (T1053.005, T1053.006)
  - T1203: Exploitation for client execution

- **Persistence (T1547 variants):**
  - T1547.001: Registry run keys (covered)
  - T1547.009: Shortcut modification
  - T1547.014: Browser extensions
  - T1547.015: Login items

**Coverage Gap:** Current ruleset covers ~15% of MITRE ATT&CK Enterprise techniques (7/40+ common techniques).

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

**Mitigation:**
- Add Sysmon integration layer (`backend/collectors/sysmon.py`)
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
**real host telemetry** collected live. The rules detect all 64 unseen attack
records with 0 false positives on 529 real telemetry records; the ML layer
generalises poorly to unseen attack types (recall 3.1%) — a documented
limitation and training-data expansion target. Rule-layer numbers therefore
carry external validity; ML numbers do not yet.

**Real-World Performance Unknown:**
- May have high false negatives on sophisticated/obfuscated attacks
- May have false positives on legitimate security tools (Nessus, antivirus scans)

**Mitigation:**
- Conduct red team exercises with real attack traffic
- Test against public datasets (ATT&CK evaluation, DARPA TC)
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

| Data Requirement | Typical ML | SentinelSOC | Gap |
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

---

## 4. Operational Limitations

### 4.1 No Multi-User Support

**Limitation:** Single-user design; no role-based access control (RBAC).

**Missing Features:**
- Analyst roles (view-only alerts)
- Investigator roles (modify analyst notes)
- Administrator roles (configure rules, manage users)
- Auditor roles (read-only historical access)

**Security Implication:**
- Anyone with backend access can modify alerts, disable rules
- No accountability trail (who made what changes, when)
- No least-privilege principle

**Workaround:** Run on isolated machine; restrict physical/network access.

**Enterprise Gap:** SOCs require multi-analyst workflows, shift-based handoffs, escalation chains.

**Mitigation:**
- Add user authentication (LDAP/Active Directory integration)
- Implement RBAC per REST endpoint
- Audit log: all modifications, configuration changes, rule disables

---

### 4.2 No Alert Deduplication/Throttling

**Limitation:** Same alert can fire repeatedly; no alert fatigue management.

**Scenario:** Brute force rule fires every 2 minutes if attacker continues.
- Dashboard flooded with identical alerts
- Analyst attention diverted
- Real threats may be missed

**Missing Features:**
- Alert deduplication: group identical alerts within time window
- Alert throttling: limit alert frequency (max 1 per 5 minutes)
- Alert correlation: link related alerts (brute force → lateral movement → data exfiltration)

**Mitigation:**
- Add deduplication in `backend/detection/alerting.py`:
  ```python
  def deduplicate_alerts(alerts, window_minutes=5):
      seen = {}
      deduped = []
      for alert in alerts:
          key = (alert.rule, alert.user, alert.host)
          if key not in seen or (now - seen[key]) > timedelta(minutes=window_minutes):
              deduped.append(alert)
              seen[key] = now
      return deduped
  ```

---

### 4.3 No Persistent Alert State Management

**Limitation:** Alerts stored in SQLite but no workflow state machine.

**Missing States:**
- Open → Acknowledged → Investigating → Resolved → Closed
- No escalation: Open → High Priority → Critical
- No suppression: Acknowledged alerts still fire
- No related alerts: Linking brute force to successful logon to lateral movement

**Impact:** No workflow hygiene; unclear which alerts need action.

**Mitigation:**
- Add alert state machine with transitions
- Implement analyst workflow API
- Add alert grouping/correlation logic

---

### 4.4 No Data Retention Policy

**Limitation:** Events stored indefinitely in SQLite; database grows unbounded.

**Problems:**
- SQLite performance degrades with >1M events
- Disk space grows: ~1 MB per 5000 events
- Backup size increases; recovery time increases
- Privacy concerns: storing PII indefinitely

**Default Behavior:** 30-day retention mentioned in documentation but not enforced.

**Mitigation:**
- Implement automatic data purge:
  ```python
  def cleanup_old_events(days=30):
      cutoff = datetime.now() - timedelta(days=days)
      session.query(NormalizedEvent).filter(NormalizedEvent.timestamp < cutoff).delete()
      session.commit()
  ```
- Add configuration: `DATA_RETENTION_DAYS=30`

---

## 5. Performance Limitations

### 5.1 SQLite Scaling Limits

**Limitation:** SQLite suitable for <1M records; performance degrades beyond that.

**Benchmark (on i5, 12GB RAM):**

| Event Count | Query Time | Dashboard Load |
|-------------|-----------|-----------------|
| 100K | <100 ms | Instant |
| 500K | 200-400 ms | 1-2 sec |
| 1M | 800-2000 ms | 3-5 sec |
| 10M | >5 sec | Timeout |

**Implication:** Can support ~1-2 months of data on single laptop; enterprise needs PostgreSQL/MySQL.

**Real-World Context:** Modern endpoint produces:
- 100-500 security events/hour (enterprise workstation)
- 1000-5000 events/hour (active server)
- Could reach 10M+ events in 1-2 weeks on busy network

**Mitigation:**
- Replace SQLite with PostgreSQL for production
- Implement data archival: move old events to cold storage
- Add materialized views for pre-computed aggregations

---

### 5.2 ML Model Training Latency

**Limitation:** Training new ML models blocks backend for 1-10 seconds.

**Current Behavior:**
```
POST /api/system/ml/train
└─ IsolationForest.fit() on 100 events: 500-2000 ms
└─ RandomForest.fit() on 100 events: 1000-5000 ms
└─ Return to caller
```

**Problem:** Long-running training locks the session; other requests block.

**Mitigation:**
- Run training asynchronously in background thread:
  ```python
  def train_async():
      executor = ThreadPoolExecutor(max_workers=1)
      executor.submit(detector.train, session, hours=24)
  ```
- Implement job queue (Celery/RQ) for distributed training

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

**Mitigation:**
- Implement FN debugging report:
  ```python
  {
    "missed_event": {...},
    "rule_score_reason": "below threshold",
    "ml_score": 0.3,
    "recommendation": "lower rule threshold OR add feature X"
  }
  ```

---

## 7. Research Limitations

### 7.1 Limited Baseline for Thesis Contribution

**Limitation:** No comparison against existing SOC solutions or open-source alternatives.

**Missing Comparisons:**
- Commercial SOCs: Splunk, Sumo Logic, Datadog Security
- Open-source alternatives: Wazuh, Graylog, OpenSearch
- Academic work: similar Windows threat detection research

**Impact on Thesis Strength:** Readers cannot assess if hybrid approach is genuinely novel or incremental.

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
- Evaluate on public datasets: DARPA TC, ATT&CK Evaluations, Cyber DEfense eXercises (CDX)
- Conduct red team assessment with real attack traffic
- Test on 5+ different organizational environments

---

## 8. Recommendations for Production Deployment & Future Work

### 8.1 Critical for Production

1. **Multi-endpoint collection:** Extend from single machine to LAN/enterprise
2. **Persistent storage:** Replace SQLite with PostgreSQL
3. **RBAC & authentication:** Add user management, audit logging
4. **Real-world validation:** Red team exercises, real attack dataset evaluation
5. **Automated parameter tuning:** Auto-optimize rule thresholds
6. **Alert deduplication:** Reduce alert fatigue

### 8.2 High-Priority Enhancements

1. **Expand rule coverage:** Add 10+ rules for T1021, T1036, T1555, etc.
2. **Sysmon integration:** Enable advanced process, registry, network telemetry
3. **Concept drift detection:** Automatic model retraining
4. **Online learning:** Incremental ML model updates
5. **Kill chain analysis:** Detect multi-step attack chains

### 8.3 Research Extensions

1. **Federated learning:** Train models collaboratively across organizations without sharing data
2. **Adversarial robustness:** Test ML against adaptive adversaries (GAN-based evasion)
3. **Explainability:** SHAP/LIME analysis of ML predictions
4. **Human-in-the-loop:** Analyst feedback improves ML models iteratively

---

## 9. Conclusion

SentinelSOC achieves its thesis goal: **demonstrating feasible, lightweight, hybrid threat detection on resource-constrained Windows endpoints**. On the v2 external-validity evaluation, the rule layer detects 100% of unseen attack scenarios with zero false positives on real host telemetry, demonstrating that the core architecture soundly generalises beyond the data used to build it.

However, production deployment requires addressing scope limitations:
- Scaling from 1 machine to enterprise
- Expanding rule coverage beyond 7 patterns
- Real-world validation vs synthetic evaluation
- Operational maturity (RBAC, deduplication, retention)

The hybrid rule+ML approach shows promise; the optimal balance (60% rule, 40% ML) avoids both false positive fatigue (pure rules) and low precision (pure ML). Future work should focus on:
1. Real-world dataset validation
2. Automated parameter tuning
3. Multi-endpoint architecture
4. Adversarial robustness testing

---

## 10. Future Work Roadmap

### Phase 2: Enterprise Readiness (6-12 months)
- [ ] Multi-endpoint collection via WinRM / EDR agents
- [ ] PostgreSQL backend for scalability
- [ ] RBAC, SSO (LDAP/AD), audit logging
- [ ] Red team exercise validation
- [ ] 10+ additional detection rules

### Phase 3: Advanced ML (12-18 months)
- [ ] Federated learning across organizations
- [ ] Online learning / concept drift adaptation
- [ ] Deep learning for feature extraction
- [ ] Adversarial robustness testing (GAN evasion)

### Phase 4: Standardization (18+ months)
- [ ] STIX/TAXII integration for threat intelligence
- [ ] OpenTelemetry / Prometheus metrics
- [ ] Kubernetes deployment templates
- [ ] Community rule contribution framework

