# ML Training Guide

This guide covers the ML training pipeline in BARAQ, including model types, training modes, and configuration.

## Overview

BARAQ uses a hybrid ML detection approach combining:

1. **Isolation Forest** - Unsupervised anomaly detection
2. **Supervised Classifier** - XGBoost/Logistic Regression for labeled data
3. **Cross-Stream Markov Chain** - Attack sequence prediction
4. **Ensemble Meta-Learner** - Combines all models for final prediction

## Training Modes

### Bulk Training

Full retraining on all available data. Use when:

- Initial deployment
- Major data distribution changes
- Model performance degrades significantly

```bash
# Via API
curl -X POST "http://localhost:8001/api/system/ml/train" \
  -H "Authorization: Bearer <token>"

# Via CLI
python scripts/train_full.py
```

### Incremental Training

Online learning updates that adapt the model to new data without full retraining.

- Triggered automatically when drift is detected
- Uses sliding window of recent events
- Preserves knowledge from previous training

### Bootstrap Training

Day-1 cold start using synthetic data. The bootstrap model provides immediate detection capability until enough real telemetry is collected.

## Configuration

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `BARAQ_ML_RETRAIN_AFTER_MINUTES` | Model staleness threshold | 5 |
| `BARAQ_ML_TARGET_FPR` | Target false positive rate | 0.03 |
| `BARAQ_ML_DRIFT_RATE` | Drift detection threshold | 0.75 |
| `BARAQ_ML_CONTAMINATION` | Expected anomaly ratio | 0.05 |
| `BARAQ_ML_BOOTSTRAP_ENABLED` | Enable bootstrap model | 1 |

### Feature Space

The current feature space (v7) includes:

**Login Events (34 features)**:
- Event ID, logon type, sub-status
- Source IP encoding
- Time features (hour sin/cos, night flag, weekend flag)
- Unusual logon type indicator
- Time since previous event
- Event rates (1h, 24h windows)
- Failed login counts (5m, 15m, 60m)
- Logon type entropy
- IP diversity
- Cross-stream features

**Process Events (24 features)**:
- Event ID
- Time features
- Encoded command indicator
- Download indicator
- Hidden window indicator
- Command line length
- LOLBin execution indicator
- Parent process risk
- Command entropy
- Time since previous event
- Event rates
- Cross-stream features

**Network Events (26 features)**:
- Connection count
- Distinct ports
- Bytes sent/received
- Duration
- Attack IP indicator
- Subnet features
- Cross-stream features

## Model Persistence

Models are saved to:
- `database/model.bundle.joblib` - Serialized model bundle
- `database/model_meta.json` - Training metadata and version history

### Version History

BARAQ keeps the last 10 training versions in metadata. Each version records:
- Training timestamp
- Sample count
- Stream configuration
- Thresholds
- Model version number

## Monitoring

### Drift Detection

The drift monitor tracks:
- **Feature-level PSI** - Population Stability Index per feature
- **Concept drift** - Prediction distribution changes
- **ADWIN** - Adaptive windowing for change point detection

### Metrics

Training metrics are logged at:
- `logs/baraq.ml.tasks` - Training progress and timing
- `GET /api/system/ml/status` - Current model status
- `GET /api/system/ml/versions` - Version history

## Troubleshooting

### Insufficient Data

If training fails with "insufficient-data":
1. Check event volume: `SELECT count(*) FROM events`
2. Ensure events have valid `raw_json`
3. Verify event types include login (4624, 4625) or process events

### High False Positives

1. Adjust `BARAQ_ML_TARGET_FPR` (increase for fewer alerts)
2. Review and label false positives to improve supervised model
3. Check for data quality issues in training data

### Model Not Training

1. Check logs for training errors
2. Verify database connectivity
3. Ensure sufficient disk space for model bundle
