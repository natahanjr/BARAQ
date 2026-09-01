# BARAQ ML API Documentation

## Overview

BARAQ's ML subsystem provides anomaly detection, behavioral analysis, and threat intelligence through a comprehensive API. This document covers all ML-related endpoints.

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
  "history": [...],
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
  "top_features": [...],
  "feature_values": {...}
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
    "labels": ["ML Detection", "Rule Customization", "Real-time Analytics", ...],
    "datasets": [
      {"label": "BARAQ", "data": [9, 10, 8, ...]},
      {"label": "Wazuh", "data": [6, 8, 5, ...]},
      {"label": "Datadog", "data": [7, 5, 9, ...]}
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
