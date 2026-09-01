# BARAQ ML System Architecture

## Overview

BARAQ's ML subsystem provides real-time anomaly detection, behavioral analysis, and threat intelligence through a multi-model ensemble architecture. This document covers all 27 ML modules, their interactions, and the data flow.

## System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           BARAQ ML System (27 modules)                        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Feature    │  │    Model     │  │   Ensemble   │  │  Deep        │     │
│  │   Engine     │  │   Training   │  │   Stacker    │  │  Features    │     │
│  │              │  │              │  │              │  │              │     │
│  │ • 38 Login   │  │ • Isolation  │  │ • Gradient   │  │ • Autoenc.   │     │
│  │ • 37 Process │  │   Forest     │  │   Boosting   │  │ • Temporal   │     │
│  │ • 34 Network │  │ • XGBoost    │  │ • Logistic   │  │   CNN        │     │
│  │              │  │ • Random     │  │   Regression │  │ • Sequence   │     │
│  │ • Cross-     │  │   Forest     │  │ • Time-      │  │   Pattern    │     │
│  │   stream     │  │              │  │   Window     │  │              │     │
│  │   features   │  │ • Multi-     │  │              │  │              │     │
│  │              │  │   contamination│ │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                │                  │                  │              │
│         ▼                ▼                  ▼                  ▼              │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                      Scoring Pipeline                                │     │
│  │                                                                      │     │
│  │  Raw Events → Feature Extraction → Model Scoring →                 │     │
│  │  Ensemble Fusion → Threshold → Alert Generation                    │     │
│  └─────────────────────────────────────────────────────────────────────┘     │
│         │                                                                     │
│         ▼                                                                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Online     │  │   Drift      │  │  Robustness  │  │  Monitoring  │     │
│  │   Learning   │  │  Detection   │  │   Testing    │  │              │     │
│  │              │  │              │  │              │  │ • TP/FP/TN/  │     │
│  │ • ADWIN      │  │ • PSI        │  │ • FGSM       │  │   FN tracking│     │
│  │ • Reservoir  │  │ • Temporal   │  │ • Cross-User │  │ • Rolling    │     │
│  │ • Active     │  │   Bias       │  │ • Cross-Env  │  │   metrics    │     │
│  │   Learning   │  │              │  │ • Cross-Plat │  │ • Prometheus │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Cross-      │  │  Attack      │  │   Insider    │  │    UEBA      │     │
│  │  Stream      │  │   Path       │  │   Threat     │  │              │     │
│  │              │  │              │  │              │  │ • Per-user   │     │
│  │ • Markov     │  │ • MITRE      │  │ • Weighted   │  │   baselines  │     │
│  │   chains     │  │   transitions│  │   risk       │  │ • Anomaly    │     │
│  │ • Attack     │  │ • Blast      │  │   scoring    │  │   detection  │     │
│  │   sequences  │  │   radius     │  │              │  │              │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Federated   │  │  Synthetic   │  │  Bootstrap   │  │  Dataset     │     │
│  │  Learning    │  │  Data Gen    │  │  Model       │  │  Import      │     │
│  │              │  │              │  │              │  │              │     │
│  │ • FedAvg     │  │ • 6 log      │  │ • Cold-start │  │ • OTRF       │     │
│  │ • Local      │  │   types      │  │   seed model │  │ • GitHub API │     │
│  │   training   │  │ • 20 attack  │  │ • Synthetic  │  │ • 100K       │     │
│  │              │  │   scenarios  │  │   corpus     │  │   dataset    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                       │
│  │  Retention   │  │  Community   │  │  Remediation │                       │
│  │              │  │  Rules       │  │              │                       │
│  │ • Archive    │  │ • Sigma      │  │ • FN         │                       │
│  │ • Prune      │  │ • Correlation│  │   analysis   │                       │
│  │ • Metrics    │  │ • Python     │  │ • Improvement│                       │
│  └──────────────┘  └──────────────┘  └──────────────┘                       │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Feature Engine (`anomaly.py`)

Extracts behavioral signals from raw Windows events:

- **Login Stream (38 features):** Authentication patterns, timing, source diversity, cross-stream correlations
- **Process Stream (37 features):** Execution patterns, command-line analysis, parent-child relationships
- **Network Stream (34 features):** Connection patterns, DNS analysis, protocol anomalies

**Key Functions:**
- `event_feature_vector()` — Extracts features from a single event
- `_get_cross_stream_features()` — Correlates events across streams
- `_get_business_hours_indicator()` — Temporal context
- `_get_kill_chain_phase()` — MITRE ATT&CK mapping
- `_calibrate_anomaly_scores()` — Sigmoid/baseline calibration
- `_select_optimal_threshold()` — Youden's J / F1-maximization

### 2. Model Training (`anomaly.py`)

**Isolation Forest (per-stream):**
- Unsupervised outlier detection
- Multi-contamination ensemble (5 models, contamination 0.01–0.15)
- Score calibration (sigmoid + baseline methods)
- Optimal threshold selection (Youden's J, F1-maximization)

**Supervised Classifier:**
- XGBoost/Random Forest for labeled data
- Cross-validated with stratified K-fold
- SMOTE augmentation for imbalanced classes

**Training Pipeline:**
1. Load events from database (configurable time window)
2. Extract feature vectors per stream
3. Train per-stream Isolation Forests
4. Train supervised classifier on labeled data
5. Train ensemble meta-learner
6. Validate and persist model bundle

### 3. Ensemble Stacker (`ensemble.py`)

Combines predictions from multiple models:

**Base Models:**
- Isolation Forest (unsupervised)
- XGBoost/Random Forest (supervised)
- Markov chain (cross-stream)

**Meta-Learner:**
- Gradient Boosting (primary)
- Logistic Regression (fallback)
- Feature-level fusion with interaction features
- Model agreement signals
- Confidence-weighted blending

**Time-Window Ensemble:**
- Sliding window of models trained at different time points
- Exponential decay weighting (newer = higher weight)
- Automatic old model expiration

### 4. Online Learning (`online.py`)

Incremental model updates without full retrain:

- **ADWIN Drift Detection:** Monitors concept drift via prequential error rate
- **Reservoir Sampling:** Statistically representative buffers with time-decay weighting
- **Active Learning:** Uncertainty-based prioritization for analyst labeling
- **Model Versioning:** Snapshots before each update with auto-rollback on degradation
- **Warm-Start Supervised:** XGBoost/RF partial_fit for incremental updates
- **Sliding-Window IF Retrain:** Isolation Forest retrained on recent window

**Key Classes:**
- `ADWINDriftDetector` — Adaptive windowing for drift detection
- `ReservoirBuffer` — Reservoir sampling with importance weights
- `ActiveLearner` — Margin sampling for uncertainty scoring
- `OnlineLearner` — Full online learning wrapper

### 5. Drift Detection (`drift.py`)

Population Stability Index (PSI) monitoring:

- **Per-stream PSI:** Login, process, network distributions
- **Temporal Bias Detection:** Hourly, daily, monthly patterns
- **Auto-retrain Trigger:** Retrains on drift detection
- **Concept Drift Monitoring:** Long-term distribution shifts

### 6. Robustness Testing (`robustness.py`)

Model validation across dimensions:

- **FGSM Adversarial Testing:** Evasion resistance
- **Cross-User Validation:** Generalization across users
- **Cross-Environment Validation:** Network environment transfer
- **Cross-Platform Validation:** Windows/Linux/macOS compatibility

### 7. Deep Learning Features (`deep_features.py`)

Neural network-based feature extraction:

- **EventAutoencoder:** Latent anomaly representations
- **TemporalCNN:** Time-series pattern detection
- **SequencePatternDetector:** Sequential behavior analysis

### 8. Cross-Stream Detection (`cross_stream.py`)

Markov chain attack sequence detection across behavior streams:

- **Attack Sequences Detected:**
  - Brute Force → Lateral Movement (failed logons → successful logon from same IP)
  - Credential Abuse → Privilege Escalation (logon → suspicious process)
  - Process Execution → Data Exfiltration (suspicious process → network)
  - Persistence → C2 Communication (service install → network)

**Key Class:** `AttackSequenceDetector`
- `update_transition()` — Update transition counts
- `compute_sequence_score()` — Anomaly score per pattern
- `analyze_event_sequence()` — Scan recent events for patterns
- `get_overall_risk_score()` — Aggregate cross-stream risk (0.0–1.0)
- `get_active_patterns()` — Active patterns with details

**Singleton:** `get_cross_stream_detector()`

### 9. Attack Path Prediction (`attack_path.py`)

Predictive modeling using entity graph and MITRE ATT&CK transitions:

- **Transition Matrix:** 14 tactic-to-tactic probabilities
- **Technique Library:** 20 techniques across 10 tactics
- **Blast Radius Analysis:** Impact assessment for compromised entities

**Key Classes:**
- `AttackStep` — Single technique step (Pydantic)
- `AttackPath` — Full predicted path (Pydantic)
- `AttackPathPredictor` — Prediction engine
  - `predict_next_steps()` — Next likely techniques
  - `build_attack_path()` — Full path from entry point
  - `analyze_blast_radius()` — Connected entity impact

### 10. Insider Threat Detection (`insider_threat.py`)

Dedicated weighted risk scoring for insider threats:

- **Risk Indicators:** Off-hours activity, data staging, large transfers, privilege escalation, unusual processes, new IPs, mass downloads, policy violations
- **Threat Levels:** NONE, LOW, MEDIUM, HIGH, CRITICAL

**Key Classes:**
- `InsiderThreatScore` — Score with indicators and actions (Pydantic)
- `InsiderThreatDetector`
  - `evaluate()` — Score user from indicator list
  - `get_score()` — Retrieve existing score
  - `list_high_risk()` — All HIGH/CRITICAL users

### 11. User and Entity Behavior Analytics (`ueba.py`)

Per-user baseline profiling and anomaly detection:

- **Baselines:** Login hours, typical hosts, processes, IPs, event frequency
- **Anomaly Detection:** Deviation from established baselines

**Key Classes:**
- `UserBaseline` — Per-user profile (Pydantic)
- `UEBAEngine`
  - `build_baseline()` — Create baseline from historical events
  - `detect_anomalies()` — Compare current events to baseline
  - `get_baseline()` — Retrieve existing baseline

### 12. Model Monitoring (`monitoring.py`)

Production accuracy tracking and health checks:

- **Rolling Metrics:** TP/FP/TN/FN in configurable window
- **Derived Metrics:** Precision, recall, F1, FPR
- **Degradation Detection:** Performance drop alerts
- **Prometheus Export:** Metrics in Prometheus format

**Key Classes:**
- `ModelMetrics` — Rolling metrics window
  - `record_prediction()` — Log prediction for later comparison
  - `record_verdict()` — Log analyst ground truth
  - `compute_metrics()` — Current rolling metrics
  - `detect_degradation()` — Performance drop detection
- `ModelMonitor` — Production monitoring wrapper
  - `check_health()` — Model health status
  - `get_prometheus_metrics()` — Prometheus text format

**Singleton:** `get_model_monitor()`

### 13. Synthetic Data Generation (`synthetic.py`)

Realistic synthetic Windows event log generator:

- **6 Log Types:** Security, PowerShell, Sysmon, Network, Application, Attack Simulation
- **20 Attack Scenarios:** Brute force, credential spray, pass-the-hash, PowerShell abuse, privilege escalation, persistence, data exfiltration, DNS tunneling, port scanning, lateral movement
- **Realistic Patterns:** Bursty timing, dormancy phases, escalation patterns
- **Enterprise Realism:** 18 users, 15 hosts, service accounts, RFC 5737 test IPs

**Key Functions:**
- `generate_synthetic_dataset()` — Full dataset across all log types
- `generate_for_ml_training()` — Flat shuffled list for ML with labels

### 14. Bootstrap Model (`bootstrap.py`)

Day-1 cold-start seed model for fresh deployments:

- **Synthetic Corpus:** 16 attack scenarios × 4 variants + 1500 benign records
- **Seeded Randomization:** Deterministic timing, addresses, user jitter
- **Isolation Forest Training:** Non-degenerate baselines on first boot
- **Auto-Superseded:** First real retrain replaces bootstrap model

**Key Functions:**
- `build_corpus()` — Deterministic synthetic corpus
- `build_bootstrap_model()` — Train and save seed model

### 15. Dataset Builder (`dataset_100k.py`)

100K event dataset from OTRF Security-Datasets:

- **206 OTRF ZIPs:** All attack scenarios from OTRF/Security-Datasets
- **Synthetic Multi-Host:** 20 realistic enterprise PCs across departments
- **28 Users:** Per-department realistic users
- **Threat Intel IPs:** Known malicious IPs for realism
- **Auto-Labeling:** Verdict table populated with ground truth

**Key Functions:**
- `build_barqaq_dataset_100k()` — Full build pipeline (download → parse → insert)

### 16. External Dataset Import (`dataset_import.py`)

Import external SOC datasets for ML training:

- **Supported Sources:** OTRF Security-Datasets, OTRF Atomic datasets
- **GitHub API Integration:** Trees API for file download
- **Background Tasks:** Non-blocking import with progress tracking
- **Deduplication:** Fingerprint-based event dedup
- **Label Propagation:** Verdict table auto-populated

**Key Classes:**
- `ImportStatus` — Task state enum (PENDING → DOWNLOADING → PARSING → LOADING → COMPLETED)
- `ImportTask` — Task state tracking (Pydantic-like dataclass)
- `ImportManager` — Background import orchestrator
  - `list_sources()` — Available datasets
  - `start_import()` — Begin background import
  - `get_task()` / `list_tasks()` — Progress tracking
  - `cancel_task()` — Cancel running import

**Singleton:** `import_manager`

### 17. Background Training Tasks (`tasks.py`)

Thread-based ML training scheduler:

- **Non-Blocking Lock:** Single training run at a time
- **Bulk Training:** O(N) training with pre-computed features
- **Online Learning Integration:** Periodic incremental updates
- **Active Learning:** Uncertain event suggestions for analysts

**Key Functions:**
- `_bulk_train()` — Bulk O(N) training
- `train_in_background()` — Thread-based training launcher
- `check_online_update()` — Periodic online learning trigger
- `get_active_learning_suggestions()` — Top uncertain events
- `training_active()` — Training status check

### 18. Federated Learning (`federated.py`)

Multi-organization model training:

- **FedAvg Protocol:** Federated averaging
- **Local Training:** Data never leaves the organization
- **Aggregator:** Combines model updates securely
- **Privacy Preservation:** No raw data sharing

### 19. Retention & Archival (`retention.py`)

ML data lifecycle management:

- **Retention Policies:** Configurable retention periods
- **Archive/Restore:** Model version archival
- **Storage Metrics:** Active/archived model counts and sizes
- **Dashboard Config:** ML dashboard configuration

### 20. Community Rules (`community_rules.py`)

Community rule contribution framework:

- **Rule Types:** Sigma (YAML), Correlation, Python-native
- **Validation:** Syntax and schema validation
- **Review Workflow:** Submit → Pending → Approve/Reject
- **Statistics:** Submission counts by type and status

### 21. Remediation Engine (`remediation.py`)

False negative analysis and improvement suggestions:

- **FN Pattern Analysis:** Cluster false negatives by attack type
- **Remediation Actions:** Feature additions, threshold tuning, model selection
- **Priority Scoring:** High/Medium/Low prioritization

### 22. SOC Comparison (`comparison.py`)

Platform capability comparison with radar charts:

- **6 Platforms:** BARAQ, Wazuh, Datadog, Sumo Logic, Microsoft Sentinel, Elastic
- **10 Dimensions:** ML detection, rule customization, real-time analytics, etc.
- **Radar Chart Data:** Recharts-compatible format
- **Recommendation Engine:** Auto-generates comparison summary

### 23. Public Dataset Evaluation (`public_datasets.py`)

ML evaluation on standardized benchmarks:

- **Datasets:** CICIDS2017, UNSW-NB15, CTU-13, MITRE
- **Adapters:** Dataset-specific parsing and normalization
- **Metrics:** Precision, recall, F1, AUC-ROC per dataset

## Data Flow

### 1. Event Ingestion
```
Windows Events → Collector → NormalizedEvent (DB)
```

### 2. Feature Extraction
```
NormalizedEvent → event_feature_vector() → Feature Matrix
```

### 3. Model Scoring
```
Feature Matrix → Isolation Forest → Anomaly Score
Feature Matrix → XGBoost → Attack Probability
Feature Matrix → Markov Chain → Sequence Probability
Feature Matrix → Autoencoder → Reconstruction Error
```

### 4. Ensemble Fusion
```
[IF Score, XGB Proba, Markov Proba, AE Error] → Meta-Learner → Final Score
```

### 5. Alert Generation
```
Final Score > Threshold → Alert (with MITRE mapping)
```

### 6. Online Learning Loop
```
New Event → Score → Buffer (Reservoir) → ADWIN Check → Update/Retrain
                                    ↓
                        Active Learning → Analyst Label → High-Weight Buffer
```

### 7. Cross-Stream Correlation
```
Login Events ─┐
Process Events ─┼→ AttackSequenceDetector → Sequence Score → Alert
Network Events ─┘
```

### 8. Attack Path Prediction
```
Compromised Entities → AttackPathPredictor → Predicted Path → Risk Score
```

## Model Persistence

**Bundle Format:**
- `model.bundle` — Serialized models (joblib)
- `model_meta.json` — Version, thresholds, feature counts
- `model.bundle.prev` — Previous version for A/B
- `bootstrap_model.joblib` — Cold-start seed model

**Version Management:**
- Automatic version bump on retrain
- Archive previous bundles
- Rollback capability

## Configuration

**Key Parameters (`config.py`):**
- `ML_FEATURE_VERSION` — Feature space version (currently 7)
- `ML_MODEL_BUNDLE` — Model file path
- `ML_MIN_SAMPLES` — Minimum training samples (10)
- `ML_RETRAIN_INTERVAL` — Retrain interval (hours)

## Performance Characteristics

- **Training Time:** ~30s for 10K events
- **Scoring Latency:** <10ms per event
- **Memory Usage:** ~500MB for full model set
- **Storage:** ~50MB for model bundles
- **Online Update:** <5s per incremental update
- **Bootstrap Model:** <10s to generate

## Security Considerations

- **Model Integrity:** SHA-256 hash verification
- **Access Control:** Admin-only training endpoints
- **Audit Logging:** All ML operations logged
- **No Secrets in Models:** Feature vectors contain no credentials
- **Federated Privacy:** No raw data sharing between organizations
