# BARAQ ML System Architecture

## Overview

BARAQ's ML subsystem provides real-time anomaly detection, behavioral analysis, and threat intelligence through a multi-model ensemble architecture. This document describes the system design, data flow, and component interactions.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        BARAQ ML System                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Feature    │  │    Model     │  │   Ensemble   │          │
│  │   Engine     │  │   Training   │  │   Stacker    │          │
│  │              │  │              │  │              │          │
│  │ • 38 Login   │  │ • Isolation  │  │ • Gradient   │          │
│  │ • 37 Process │  │   Forest     │  │   Boosting   │          │
│  │ • 34 Network │  │ • XGBoost    │  │ • Logistic   │          │
│  │              │  │ • Random     │  │   Regression │          │
│  │ • Cross-     │  │   Forest     │  │ • Time-      │          │
│  │   stream     │  │              │  │   Window     │          │
│  │   features   │  │ • Multi-     │  │              │          │
│  │              │  │   contamination│ │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│         │                │                  │                   │
│         ▼                ▼                  ▼                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Scoring Pipeline                      │   │
│  │                                                         │   │
│  │  Raw Events → Feature Extraction → Model Scoring →     │   │
│  │  Ensemble Fusion → Threshold → Alert Generation        │   │
│  └─────────────────────────────────────────────────────────┘   │
│         │                                                       │
│         ▼                                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Online     │  │   Drift      │  │  Robustness  │          │
│  │   Learning   │  │  Detection   │  │   Testing    │          │
│  │              │  │              │  │              │          │
│  │ • ADWIN      │  │ • PSI        │  │ • FGSM       │          │
│  │ • Reservoir  │  │ • Temporal   │  │ • Cross-User │          │
│  │ • Active     │  │   Bias       │  │ • Cross-Env  │          │
│  │   Learning   │  │              │  │ • Cross-Plat │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Feature Engine (`anomaly.py`)

The feature engine extracts behavioral signals from raw Windows events:

- **Login Stream (38 features):** Authentication patterns, timing, source diversity, cross-stream correlations
- **Process Stream (37 features):** Execution patterns, command-line analysis, parent-child relationships
- **Network Stream (34 features):** Connection patterns, DNS analysis, protocol anomalies

**Key Functions:**
- `event_feature_vector()` — Extracts features from a single event
- `_get_cross_stream_features()` — Correlates events across streams
- `_get_business_hours_indicator()` — Temporal context
- `_get_kill_chain_phase()` — MITRE ATT&CK mapping

### 2. Model Training (`anomaly.py`)

**Isolation Forest (per-stream):**
- Unsupervised outlier detection
- Multi-contamination ensemble (5 models, contamination 0.01-0.15)
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

- **ADWIN Drift Detection:** Monitors concept drift
- **Reservoir Sampling:** Maintains representative buffers
- **Active Learning:** Identifies uncertain events for analyst labeling
- **Incremental Updates:** Updates model parameters incrementally

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

### 8. Federated Learning (`federated.py`)

Multi-organization model training:

- **FedAvg Protocol:** Federated averaging
- **Local Training:** Data never leaves the organization
- **Aggregator:** Combines model updates securely
- **Privacy Preservation:** No raw data sharing

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
```

### 4. Ensemble Fusion
```
[IF Score, XGB Proba, Markov Proba] → Meta-Learner → Final Score
```

### 5. Alert Generation
```
Final Score > Threshold → Alert (with MITRE mapping)
```

## Model Persistence

**Bundle Format:**
- `model.bundle` — Serialized models (joblib)
- `model_meta.json` — Version, thresholds, feature counts
- `model.bundle.prev` — Previous version for A/B

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

## Security Considerations

- **Model Integrity:** SHA-256 hash verification
- **Access Control:** Admin-only training endpoints
- **Audit Logging:** All ML operations logged
- **No Secrets in Models:** Feature vectors contain no credentials
