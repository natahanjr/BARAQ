# BARAQ ML API Documentation

## Overview

BARAQ's ML subsystem provides anomaly detection, behavioral analysis, and threat intelligence through a comprehensive API. This document covers all ML-related endpoints across the platform.

## Authentication

All ML endpoints require authentication via Bearer token or API key. Admin-only endpoints are marked with `[Admin]`.

---

## Core ML Endpoints

### POST `/api/system/ml/train` [Admin]

Train or retrain ML models.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `async_mode` | bool | `true` | Run training in background |
| `hours` | int | `None` | Training window in hours (None = full history) |
| `force` | bool | `false` | Skip validation, force retrain |

**Response:**
```json
{
  "scheduled": true,
  "force": false,
  "window": "last 24h",
  "message": "Background training started (last 24h).",
  "training": false
}
```

---

### POST `/api/system/ml/analyze` [Admin]

Run anomaly scan on recent events.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hours` | int | `1` | Scan window in hours (1-168) |

**Response:**
```json
{
  "status": "ok",
  "scored": 1250,
  "flagged": 3
}
```

---

### GET `/api/system/ml/status`

Get ML model status, version, and health metrics.

**Response:**
```json
{
  "model_state": "HEALTHY",
  "model_version": "7",
  "version": "7",
  "train_kind": "initial",
  "scored_events": 15420,
  "training": false,
  "trained_at": "2026-09-01T10:00:00Z",
  "drift": false,
  "stale": false,
  "ready": true,
  "ensemble": {
    "is_trained": true,
    "active_meta_learner": "logistic_regression",
    "meta_weights": {"if": 0.6, "supervised": 0.4}
  },
  "online_learning": true,
  "feature_version": 7,
  "models_trained": ["login", "process", "network"]
}
```

---

### GET `/api/system/ml/versions`

Model version history for A/B comparisons.

**Response:**
```json
{
  "serving_version": "7",
  "trained_at": "2026-09-01T10:00:00Z",
  "train_kind": "initial",
  "history": [],
  "prev_bundle_available": true,
  "note": "previous bundle is archived for A/B at model.bundle.prev.joblib"
}
```

---

### GET `/api/system/ml/drift`

PSI drift detection over recent features.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hours` | int | `12` | Drift check window (1-168) |

**Response:**
```json
{
  "status": "ok",
  "streams": {
    "login": {"psi": 0.12, "verdict": "ok"},
    "process": {"psi": 0.08, "verdict": "ok"},
    "network": {"psi": 0.15, "verdict": "watch"}
  }
}
```

---

### GET `/api/system/ml/explain/alert/{alert_id}`

SHAP/LIME explanation for an alert's anomaly score.

**Response:**
```json
{
  "alert_id": 12345,
  "explanations": [
    {
      "event_id": 67890,
      "behavior": "login",
      "score": 0.92,
      "top_features": [
        {"feature": "source_ip_diversity", "contribution": 0.35},
        {"feature": "failed_login_velocity_1h", "contribution": 0.28}
      ]
    }
  ]
}
```

---

### GET `/api/system/ml/explain/event/{event_id}`

Explain a single event's anomaly score.

**Response:**
```json
{
  "event_id": 67890,
  "behavior": "login",
  "score": 0.87,
  "threshold": 0.59,
  "is_anomaly": true,
  "top_features": [],
  "feature_values": {}
}
```

---

## Advanced ML Endpoints

### GET `/api/system/ml/robustness`

Model robustness testing results.

**Response:**
```json
{
  "status": "ok",
  "models_ready": true,
  "cross_user": {
    "generalization_score": 0.85,
    "user_variance": 0.12
  },
  "cross_environment": {
    "environment_generalization": 0.78
  },
  "cross_platform": {
    "platforms_tested": ["windows", "linux", "macos"],
    "cross_platform_score": 0.72
  }
}
```

---

### GET `/api/system/ml/online-learning`

Online learning status and active learning suggestions.

**Response:**
```json
{
  "status": "ok",
  "online_learner_available": true,
  "should_update": false,
  "active_learning_suggestions": 5,
  "suggestions": [
    {"event_id": 12345, "uncertainty": 0.48},
    {"event_id": 12346, "uncertainty": 0.45}
  ]
}
```

---

### GET `/api/system/ml/temporal-bias`

Temporal bias detection across hourly, daily, and monthly distributions.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `hours` | int | `24` | Analysis window (1-168) |

**Response:**
```json
{
  "status": "ok",
  "any_bias_detected": false,
  "max_psi": 0.15,
  "hourly": {
    "bias_detected": false,
    "psi": 0.12,
    "description": "Normal"
  },
  "daily": {
    "bias_detected": false,
    "psi": 0.08,
    "description": "Normal"
  },
  "monthly": {
    "bias_detected": false,
    "psi": 0.15,
    "description": "Normal"
  },
  "recommendation": "No temporal bias detected"
}
```

---

### GET `/api/system/ml/federated`

Federated learning capabilities and status.

**Response:**
```json
{
  "status": "ok",
  "available": true,
  "aggregator_class": "FederatedAggregator",
  "client_class": "FederatedClient",
  "description": "FedAvg-based federated learning for multi-organization collaboration"
}
```

---

### GET `/api/system/ml/community-rules`

Community rule contribution framework status.

**Response:**
```json
{
  "status": "ok",
  "statistics": {
    "total_submitted": 15,
    "by_type": {"sigma": 10, "correlation": 3, "python_native": 2},
    "by_status": {"approved": 8, "pending": 5, "rejected": 2}
  },
  "rule_types": ["sigma", "correlation", "python_native"]
}
```

---

### GET `/api/system/ml/remediation`

FN remediation suggestions from false negative analysis.

**Response:**
```json
{
  "status": "ok",
  "summary": {
    "fn_summary": {
      "total": 12,
      "attack_types": ["brute_force", "lateral_movement"],
      "avg_ml_score": 0.35
    },
    "remediation_actions": {
      "count": 3,
      "actions": [
        {"type": "feature_addition", "priority": "high", "description": "Add geo-distance feature"}
      ]
    }
  }
}
```

---

### GET `/api/system/ml/comparison`

SOC platform comparison radar chart data.

**Response:**
```json
{
  "status": "ok",
  "radar_chart": {
    "labels": ["ML Detection", "Rule Customization", "Real-time Analytics"],
    "datasets": [
      {"label": "BARAQ", "data": [9, 10, 8]},
      {"label": "Wazuh", "data": [6, 8, 5]}
    ]
  },
  "recommendation": {
    "recommendation": "BARAQ leads in ML capabilities, customization, and cost.",
    "key_advantages": ["Full ML pipeline", "Open source", "No vendor lock-in"]
  }
}
```

---

### GET `/api/system/ml/retention`

ML data retention and archival status.

**Response:**
```json
{
  "status": "ok",
  "storage_metrics": {
    "active_models": 3,
    "archived_models": 5,
    "archive_size_mb": 45.2,
    "total_size_mb": 52.8
  }
}
```

---

### GET `/api/system/ml/ensemble`

Ensemble stacker status and model weights.

**Response:**
```json
{
  "status": "ok",
  "ensemble": {
    "is_trained": true,
    "has_sklearn": true,
    "active_meta_learner": "logistic_regression",
    "meta_weights": {
      "if": 0.6,
      "supervised": 0.4,
      "markov": 0.0
    },
    "min_samples_required": 30
  }
}
```

---

## UEBA Endpoints

### GET `/api/ueba/baselines`

List all user behavior baselines.

**Response:**
```json
{
  "baselines": [
    {
      "username": "jsmith",
      "login_hours": [9, 10, 11, 14, 15, 16],
      "typical_hosts": ["WORKSTATION01", "WORKSTATION02"],
      "typical_processes": ["chrome.exe", "outlook.exe"],
      "event_count_30d": 15420,
      "avg_daily_events": 514.0,
      "risk_score": 0.12
    }
  ],
  "total": 28
}
```

### GET `/api/ueba/baseline/{username}`

Get baseline for a specific user.

**Response:**
```json
{
  "username": "jsmith",
  "login_hours": [9, 10, 11, 14, 15, 16],
  "typical_hosts": ["WORKSTATION01"],
  "typical_processes": ["chrome.exe"],
  "typical_ips": ["10.10.1.50"],
  "event_count_30d": 15420,
  "avg_daily_events": 514.0,
  "unique_days_active": 22,
  "risk_score": 0.12
}
```

### POST `/api/ueba/detect`

Detect anomalies against user baselines.

**Request Body:**
```json
{
  "username": "jsmith",
  "events": [{"event_id": 12345, "timestamp": "...", "host": "..."}]
}
```

**Response:**
```json
{
  "anomalies": [
    {"type": "unusual_host", "description": "Login from unknown host", "severity": "medium"},
    {"type": "off_hours", "description": "Activity at 3:00 AM", "severity": "low"}
  ],
  "total_anomalies": 2
}
```

---

## Insider Threat Endpoints

### GET `/api/insider-threat/scores`

List all insider threat scores.

**Response:**
```json
{
  "scores": [
    {
      "username": "admin",
      "threat_level": "high",
      "score": 75.0,
      "indicators": ["off_hours_activity", "large_transfer", "privilege_escalation"],
      "recommended_actions": ["Review recent file access", "Check for data staging"]
    }
  ],
  "high_risk_count": 1
}
```

### GET `/api/insider-threat/score/{username}`

Get threat score for a specific user.

**Response:**
```json
{
  "username": "admin",
  "threat_level": "high",
  "score": 75.0,
  "indicators": ["off_hours_activity", "large_transfer"],
  "recommended_actions": ["Review recent file access"]
}
```

### POST `/api/insider-threat/evaluate`

Evaluate user for insider threat indicators.

**Request Body:**
```json
{
  "username": "admin",
  "indicators": ["off_hours_activity", "data_staging", "large_transfer"]
}
```

**Response:**
```json
{
  "username": "admin",
  "threat_level": "critical",
  "score": 85.0,
  "indicators": ["off_hours_activity", "data_staging", "large_transfer"],
  "recommended_actions": ["Immediate access review", "Isolate account", "Escalate to SOC"]
}
```

---

## Attack Path Endpoints

### GET `/api/attack-path/predict`

Predict next attack steps.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `current_tactics` | str | (required) | Comma-separated current tactics |
| `top_k` | int | `3` | Number of predictions |

**Response:**
```json
{
  "predictions": [
    {
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "tactic": "credential-access",
      "probability": 0.85,
      "from_entity": "WORKSTATION01",
      "to_entity": "DC01"
    }
  ],
  "total": 3
}
```

### POST `/api/attack-path/build`

Build full attack path from entry point.

**Request Body:**
```json
{
  "entry_tactic": "initial-access",
  "compromised_tactics": ["execution", "persistence"],
  "path_id": "path-001"
}
```

**Response:**
```json
{
  "path_id": "path-001",
  "steps": [
    {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "initial-access", "probability": 1.0},
    {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": "execution", "probability": 0.85},
    {"technique_id": "T1053", "technique_name": "Scheduled Task/Job", "tactic": "persistence", "probability": 0.70}
  ],
  "risk_score": 0.78,
  "entry_point": "initial-access",
  "predicted_target": "exfiltration",
  "confidence": 0.72
}
```

### POST `/api/attack-path/blast-radius`

Analyze blast radius for compromised entity.

**Request Body:**
```json
{
  "compromised_entity": "WORKSTATION01",
  "connected_entities": ["DC01", "FILE01", "SQL01", "WEB01"]
}
```

**Response:**
```json
{
  "compromised_entity": "WORKSTATION01",
  "connected_count": 4,
  "risk_score": 0.65,
  "high_risk_entities": ["DC01", "SQL01"],
  "recommendation": "Isolate WORKSTATION01 immediately"
}
```

---

## Cross-Stream Detection Endpoints

### GET `/api/system/ml/cross-stream`

Get cross-stream attack sequence detection status.

**Parameters:**
| Name | Type | Default | Description |
|------|------|---------|-------------|
| `window_minutes` | int | `60` | Analysis window in minutes |

**Response:**
```json
{
  "status": "ok",
  "overall_risk_score": 0.35,
  "active_patterns": [
    {
      "pattern": "brute_force_lateral",
      "description": "Failed logons followed by successful logon from same IP",
      "score": 0.72,
      "time_window_seconds": 3600,
      "min_transitions": 3
    }
  ],
  "total_patterns": 4
}
```

---

## Model Monitoring Endpoints

### GET `/api/system/ml/monitoring`

Get production model monitoring metrics.

**Response:**
```json
{
  "status": "ok",
  "metrics": {
    "precision": 0.92,
    "recall": 0.87,
    "f1": 0.89,
    "fpr": 0.05,
    "total_predictions": 15420,
    "total_verdicts": 1250
  },
  "health": {
    "status": "healthy",
    "degradation_detected": false,
    "recommendation": "Model performing within expected parameters"
  }
}
```

### GET `/api/system/ml/monitoring/prometheus`

Export metrics in Prometheus text format.

**Response:**
```
# HELP baraq_ml_precision Model precision
# TYPE baraq_ml_precision gauge
baraq_ml_precision 0.92
# HELP baraq_ml_recall Model recall
# TYPE baraq_ml_recall gauge
baraq_ml_recall 0.87
# HELP baraq_ml_f1 Model F1 score
# TYPE baraq_ml_f1 gauge
baraq_ml_f1 0.89
```

### POST `/api/system/ml/monitoring/verdict`

Record analyst verdict for ground truth.

**Request Body:**
```json
{
  "event_id": 12345,
  "true_label": "attack",
  "analyst": "analyst_1"
}
```

**Response:**
```json
{
  "status": "ok",
  "message": "Verdict recorded"
}
```

---

## Dataset Management Endpoints

### GET `/api/ml-dataset/sources`

List available dataset sources.

**Response:**
```json
{
  "sources": [
    {
      "id": "security_datasets",
      "name": "OTRF Security-Datasets",
      "description": "Pre-labeled attack/benign datasets with MITRE ATT&CK mappings",
      "format": "OCSF JSON/Zeek",
      "download_mode": "api_files"
    }
  ],
  "total": 2
}
```

### POST `/api/ml-dataset/import`

Start background dataset import.

**Request Body:**
```json
{
  "dataset": "security_datasets",
  "max_events": 10000,
  "github_token": "ghp_..."
}
```

**Response:**
```json
{
  "task_id": "import-abc123",
  "dataset": "security_datasets",
  "status": "pending",
  "message": "Import started"
}
```

### GET `/api/ml-dataset/tasks`

List all import tasks.

**Response:**
```json
{
  "tasks": [
    {
      "task_id": "import-abc123",
      "dataset": "security_datasets",
      "status": "loading",
      "progress": 65.0,
      "total_events": 10000,
      "loaded_events": 6500,
      "started_at": "2026-09-01T10:00:00Z"
    }
  ],
  "total": 1
}
```

### GET `/api/ml-dataset/task/{task_id}`

Get specific import task status.

**Response:**
```json
{
  "task_id": "import-abc123",
  "dataset": "security_datasets",
  "status": "completed",
  "progress": 100.0,
  "total_events": 10000,
  "loaded_events": 10000,
  "skipped_events": 0,
  "completed_at": "2026-09-01T10:05:00Z"
}
```

### DELETE `/api/ml-dataset/task/{task_id}`

Cancel a running import task.

**Response:**
```json
{
  "status": "ok",
  "message": "Task cancelled"
}
```

### POST `/api/ml-dataset/build-100k`

Build the BARAQ Dataset 100K (OTRF + synthetic).

**Request Body:**
```json
{
  "max_zip_size_mb": 10
}
```

**Response:**
```json
{
  "status": "ok",
  "otrf_events": 45000,
  "synthetic_events": 55000,
  "total_events": 100000,
  "hosts": 20,
  "users": 28,
  "message": "BARAQ Dataset 100K built successfully"
}
```

---

## Feature Vectors

### Login Stream (38 features)
- event_id, logon_type, sub_status, source_host, is_locked
- hour_sin, hour_cos, is_night, is_weekend, unusual_logon_type
- time_since_last_login, logins_last_hour, logins_last_day
- threat_intel_score, failed_login_velocity_5m/15m/1h
- logon_type_entropy, source_ip_diversity, time_between_logins_zscore
- privilege_escalation_indicator, recent_failed_logins
- recent_suspicious_processes, recent_network_connections
- login_process_ratio, time_since_last_any
- has_failed_then_process, has_process_then_network, event_diversity
- business_hours_indicator, event_burst_score, kill_chain_phase
- session_duration_deviation, user_attack_frequency
- auth_protocol_indicator, failed_success_ratio
- distinct_source_ips, hour_distribution_entropy

### Process Stream (37 features)
- event_id, has_encoded, has_download, has_hidden, group_sid
- script_len, cmdline_len, hour_sin, hour_cos, has_remote
- time_since_last_process, processes_last_hour, processes_last_day
- threat_intel_score, parent_child_anomaly, commandline_entropy
- process_frequency_per_user, lolbin_abuse_indicator, new_process_path
- recent_failed_logins, recent_suspicious_processes
- recent_network_connections, login_process_ratio
- time_since_last_any, has_failed_then_process
- has_process_then_network, event_diversity
- business_hours_indicator, event_burst_score, kill_chain_phase
- process_risk_proxy, process_attack_frequency
- executable_path_entropy, system_directory_indicator
- parent_process_risk, commandline_token_count, process_chain_depth

### Network Stream (34 features)
- is_private, is_testnet, is_link_local
- first_octet, second_octet, is_class_a/b/c
- connection_count, distinct_ports, bytes_sent_mb, bytes_recv_mb
- duration_h, send_rate, connection_velocity
- port_scan_indicator, exfiltration_indicator, beaconing_indicator
- dns_query_pattern, burst_velocity, kill_chain_phase
- attack_history, connections_per_minute, port_scan_trend
- dns_tunnel_indicator, dns_long_label_indicator
- protocol_anomaly_score, tls_https_ratio
- connection_diversity, data_volume_asymmetry
- connection_regularity, outbound_connection_ratio
- is_novel, hour

---

## Error Responses

All endpoints return standard error formats:

```json
{
  "detail": "Error message describing what went wrong"
}
```

**Common HTTP Status Codes:**
| Code | Description |
|------|-------------|
| `200` | Success |
| `400` | Bad request / invalid parameters |
| `401` | Unauthorized (missing/invalid token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Resource not found |
| `409` | Conflict (e.g., training already in progress) |
| `422` | Validation error |
| `500` | Internal server error |

---

## Rate Limits

| Endpoint Group | Limit | Window |
|----------------|-------|--------|
| `/api/system/ml/*` | 60 req/min | Sliding window |
| `/api/ueba/*` | 30 req/min | Sliding window |
| `/api/insider-threat/*` | 30 req/min | Sliding window |
| `/api/attack-path/*` | 30 req/min | Sliding window |
| `/api/ml-dataset/*` | 10 req/min | Sliding window |

Rate limit headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Window reset time (Unix timestamp)
