# BARAQ ML Deployment Guide

## Prerequisites

- Python 3.13+
- PostgreSQL 14+
- Node.js 18+ (for frontend)
- Redis 7+ (for caching and federated learning)
- 4GB+ RAM recommended (8GB+ for deep learning)
- 10GB+ disk space

## Installation

### 1. Clone Repository
```bash
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

**Required ML Packages:**
- `scikit-learn>=1.3.0`
- `xgboost>=2.0.0`
- `numpy>=1.24.0`
- `joblib>=1.3.0`
- `pydantic>=2.0.0`

**Optional Deep Learning:**
```bash
pip install torch torchvision  # For autoencoder features (EventAutoencoder, TemporalCNN)
```

**Optional - SHAP/LIME (explainability):**
```bash
pip install shap lime  # For model explainability
```

### 3. Install Frontend Dependencies
```bash
cd frontend
npm install
npm run build
```

### 4. Configure Environment
```bash
# Create .env file
cat > .env << EOF
DATABASE_URL=postgresql+psycopg://postgres:password@localhost:5432/baraq
SECRET_KEY=your-secret-key-here
CORS_ORIGINS=http://localhost:5173
REDIS_URL=redis://localhost:6379/0
EOF
```

### 5. Initialize Database
```bash
alembic upgrade head
```

### 6. Start Services
```bash
# Backend
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

# Frontend (development)
cd frontend
npm run dev

# Redis (if not running as service)
redis-server
```

## ML System Setup

### Initial Training

```bash
# Via API
curl -X POST http://localhost:8000/api/system/ml/train?async_mode=false

# Via CLI
python -c "from backend.ml.anomaly import get_detector; get_detector().train()"
```

### Bootstrap Model (Day-1 Cold Start)

A fresh BARAQ deployment starts with a bootstrap model trained on synthetic data:

```bash
# Generate bootstrap model
python -c "from backend.ml.bootstrap import build_bootstrap_model; build_bootstrap_model()"

# The bootstrap model is automatically loaded when no locally-trained bundle exists
# First real retrain supersedes it
```

### Build 100K Dataset

```bash
# Via API
curl -X POST http://localhost:8000/api/ml-dataset/build-100k

# Via CLI
python -c "from backend.ml.dataset_100k import build_barqaq_dataset_100k; build_barqaq_dataset_100k()"
```

### Import External Datasets

```bash
# List available sources
curl http://localhost:8000/api/ml-dataset/sources

# Start import
curl -X POST http://localhost:8000/api/ml-dataset/import \
  -H "Content-Type: application/json" \
  -d '{"dataset": "security_datasets", "max_events": 10000}'
```

### Verify Installation

```bash
# Check ML status
curl http://localhost:8000/api/system/ml/status

# Expected response:
# {
#   "model_state": "HEALTHY",
#   "version": "7",
#   "ready": true,
#   ...
# }
```

## Configuration Options

### Model Configuration (`backend/config.py`)

```python
# Feature version (bump on feature changes)
ML_FEATURE_VERSION = 7

# Minimum samples per stream for training
ML_MIN_SAMPLES = 10

# Retrain interval (hours)
ML_RETRAIN_INTERVAL = 24

# Drift threshold (PSI)
ML_PSI_ALERT = 0.25
ML_PSI_WATCH = 0.15

# Model bundle path
ML_MODEL_BUNDLE = "backend/ml/model.bundle"
```

### Online Learning Configuration

```python
# Online learner parameters (in online.py)
buffer_size = 2048          # Reservoir buffer size
min_new_events = 50         # Events before triggering update
min_new_verdicts = 5        # Verdicts before triggering update
update_interval_minutes = 15 # Minimum minutes between updates
adwin_delta = 0.002         # ADWIN drift detection confidence
analyst_weight = 5.0        # Weight for analyst-confirmed labels
time_decay = 0.999          # Reservoir time-decay factor
```

### Cross-Stream Detection

```python
# Attack sequences (in cross_stream.py)
# Pre-defined patterns with transition probabilities:
# - brute_force_lateral: Failed logons → successful logon (1h window)
# - credential_privilege: Logon → suspicious process (30m window)
# - process_exfil: Suspicious process → network (15m window)
# - persistence_c2: Service install → network (1h window)
```

### Insider Threat Weights

```python
# Risk weights (in insider_threat.py)
RISK_WEIGHTS = {
    "off_hours_activity": 15,
    "data_staging": 25,
    "large_transfer": 25,
    "privilege_escalation": 35,
    "unusual_process": 20,
    "new_ip": 10,
    "mass_download": 20,
    "policy_violation": 15,
}
```

### Training Windows

```python
# Full history (default)
train(hours=None)

# Last 24 hours
train(hours=24)

# Last 7 days
train(hours=168)
```

## Production Deployment

### Docker

```bash
# Build image
docker build -t baraq .

# Run container
docker run -d \
  --name baraq \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql+psycopg://user:pass@host:5432/baraq \
  -e SECRET_KEY=your-secret-key \
  -e REDIS_URL=redis://redis:6379/0 \
  baraq
```

### Docker Compose

```yaml
version: '3.8'
services:
  baraq:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+psycopg://postgres:password@db:5432/baraq
      - SECRET_KEY=your-secret-key
      - REDIS_URL=redis://redis:6379/0
    depends_on:
      - db
      - redis

  db:
    image: postgres:16
    environment:
      - POSTGRES_DB=baraq
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

### Systemd Service

```ini
[Unit]
Description=BARAQ Security Platform
After=network.target postgresql.service redis.service

[Service]
Type=simple
user=baraq
working-directory=/opt/baraq
ExecStart=/opt/baraq/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
Environment=DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/baraq
Environment=SECRET_KEY=your-secret-key
Environment=REDIS_URL=redis://localhost:6379/0

[Install]
WantedBy=multi-user.target
```

## Authentication Setup

### JWT Configuration

```python
# JWT settings (in backend/api/auth.py)
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7
```

### MFA (TOTP) Setup

```bash
# Enable MFA for a user
curl -X POST http://localhost:8000/api/auth/mfa/enable \
  -H "Authorization: Bearer <token>"

# Verify TOTP code
curl -X POST http://localhost:8000/api/auth/mfa/verify \
  -H "Authorization: Bearer <token>" \
  -d '{"code": "123456"}'
```

### OIDC Configuration

```python
# OIDC settings (in backend/api/auth.py)
OIDC_CLIENT_ID = "your-client-id"
OIDC_CLIENT_SECRET = "your-client-secret"
OIDC_ISSUER = "https://your-oidc-provider.com"
OIDC_REDIRECT_URI = "http://localhost:8000/api/auth/oidc/callback"
```

## TLS/mTLS Agent Configuration

```yaml
# Agent TLS config
agent:
  tls:
    enabled: true
    cert_file: "/etc/baraq/agent.crt"
    key_file: "/etc/baraq/agent.key"
    ca_file: "/etc/baraq/ca.crt"
    verify_hostname: true
```

## Monitoring

### Health Checks

```bash
# Readiness probe
curl http://localhost:8000/api/health

# Liveness probe
curl http://localhost:8000/api/live

# ML-specific health
curl http://localhost:8000/api/system/ml/status

# Model monitoring
curl http://localhost:8000/api/system/ml/monitoring
```

### Metrics (Prometheus)

```bash
# Metrics endpoint
curl http://localhost:8000/metrics

# ML-specific metrics (Prometheus format)
curl http://localhost:8000/api/system/ml/monitoring/prometheus

# Key ML metrics:
# - baraq_ml_precision (gauge)
# - baraq_ml_recall (gauge)
# - baraq_ml_f1 (gauge)
# - baraq_ml_fpr (gauge)
# - baraq_ml_total_predictions (counter)
# - baraq_ml_total_verdicts (counter)
```

### Prometheus Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'baraq'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'baraq-ml'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/api/system/ml/monitoring/prometheus'
    scrape_interval: 60s
```

### Grafana Dashboard

Import the BARAQ ML dashboard using the metrics above:
- Model precision/recall/F1 over time
- FPR (false positive rate) trends
- Drift PSI per stream
- Online learning update frequency
- Prediction volume

### Logging

```bash
# ML subsystem logs
tail -f /var/log/baraq/ml.log

# Or via journalctl
journalctl -u baraq -f

# Log levels
# baraq.ml.anomaly    - Model training/scoring
# baraq.ml.online     - Online learning updates
# baraq.ml.cross_stream - Cross-stream detection
# baraq.ml.monitoring - Production metrics
# baraq.ml.tasks      - Background training
```

### Log Rotation

```bash
# /etc/logrotate.d/baraq
/var/log/baraq/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 baraq baraq
    sharedscripts
    postrotate
        systemctl reload baraq > /dev/null 2>&1 || true
    endscript
}
```

## Troubleshooting

### Model Not Training

```bash
# Check database connection
python -c "from backend.database.connection import SessionLocal; SessionLocal()"

# Check event count
python -c "
from backend.database.models import NormalizedEvent
from backend.database.connection import SessionLocal
db = SessionLocal()
count = db.query(NormalizedEvent).count()
print(f'Events: {count}')
db.close()
"

# Force retrain
curl -X POST "http://localhost:8000/api/system/ml/train?force=true&async_mode=false"
```

### Low Accuracy

```bash
# Check feature count
python -c "
from backend.ml.explain import FEATURE_NAMES
for k, v in FEATURE_NAMES.items():
    print(f'{k}: {len(v)} features')
"

# Run robustness tests
curl http://localhost:8000/api/system/ml/robustness

# Check drift
curl http://localhost:8000/api/system/ml/drift

# Check model monitoring
curl http://localhost:8000/api/system/ml/monitoring
```

### Online Learning Not Updating

```bash
# Check online learning status
curl http://localhost:8000/api/system/ml/online-learning

# Check if ADWIN drift detected
python -c "
from backend.ml.online import OnlineLearner
from backend.ml.anomaly import get_detector
learner = OnlineLearner(get_detector())
print(learner.status())
"
```

### High Memory Usage

```bash
# Check model size
ls -lh backend/ml/model.bundle*

# Reduce model complexity
# Edit config.py:
# ML_MIN_SAMPLES = 20  # Increase minimum samples

# Check online learner buffer size
python -c "
from backend.ml.online import OnlineLearner
from backend.ml.anomaly import get_detector
learner = OnlineLearner(get_detector(), buffer_size=1024)  # Reduce from default 2048
"
```

## Backup and Recovery

### Backup Models

```bash
# Backup model bundle
cp backend/ml/model.bundle /backup/model.bundle.$(date +%Y%m%d)

# Backup metadata
cp backend/ml/model_meta.json /backup/model_meta.$(date +%Y%m%d).json

# Backup bootstrap model
cp backend/ml/assets/bootstrap_model.joblib /backup/
```

### Restore Models

```bash
# Restore from backup
cp /backup/model.bundle.20260901 backend/ml/model.bundle
cp /backup/model_meta.20260901.json backend/ml/model_meta.json

# Restart service
systemctl restart baraq
```

### Archive Management

```bash
# List archives
curl http://localhost:8000/api/system/ml/retention

# Prune old versions (keep last 5)
python -c "
from backend.ml.retention import MLDataRetention
retention = MLDataRetention(model_dir='backend/ml', archive_dir='backend/ml/archives')
retention.prune_old_versions(keep_versions=5)
"
```

## Performance Tuning

### Training Optimization

```python
# Parallel training (if multiple cores)
import os
os.environ["OMP_NUM_THREADS"] = "4"

# Reduce feature space for faster training
ML_FEATURE_VERSION = 7  # Use subset of features

# Use bulk training for large datasets
from backend.ml.tasks import _bulk_train
_bulk_train(session, hours=24)  # O(N) training
```

### Scoring Optimization

```python
# Batch scoring for high throughput
events = [event1, event2, ...]
scores = detector.score_events(events)

# Cache frequently accessed models
from functools import lru_cache
@lru_cache(maxsize=32)
def get_cached_model(stream):
    return detector.models[stream]
```

### Online Learning Optimization

```python
# Tune buffer size for your workload
from backend.ml.online import OnlineLearner, ReservoirBuffer

# Smaller buffer = faster updates, less memory
buffer = ReservoirBuffer(max_size=1024, time_decay=0.999)

# Adjust update frequency
learner = OnlineLearner(
    detector,
    buffer_size=1024,
    min_new_events=25,        # More frequent updates
    update_interval_minutes=5 # Every 5 minutes
)
```

## Security Hardening

### Model Security

```bash
# Verify model integrity
sha256sum backend/ml/model.bundle

# Set restrictive permissions
chmod 600 backend/ml/model.bundle
chmod 600 backend/ml/model_meta.json
chmod 600 backend/ml/assets/bootstrap_model.joblib
```

### API Security

```python
# Rate limiting (in main.py)
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@router.get("/ml/status")
@limiter.limit("10/minute")
def ml_status(request: Request):
    ...
```

### Audit Logging

```python
# Log all ML operations
import logging
logger = logging.getLogger("baraq.ml.audit")

def train_with_audit(session, hours=None):
    logger.info("ML training started: hours=%s", hours)
    result = detector.train(session, hours=hours)
    logger.info("ML training completed: %s", result)
    return result
```

## Scaling

### Horizontal Scaling

```yaml
# Multiple worker instances
services:
  baraq:
    deploy:
      replicas: 3
    environment:
      - REDIS_URL=redis://redis:6379
```

### Model Sharing

```python
# Federated learning setup
from backend.ml.federated import FederatedAggregator, FederatedClient

# Organization A (aggregator)
agg = FederatedAggregator(min_clients=3)

# Organization B (client)
client = FederatedClient(client_id="org_b", aggregator=agg)
client.train_local()
client.upload_update()
```

## ML Module Reference

| Module | Purpose | Key Classes |
|--------|---------|-------------|
| `anomaly.py` | Core ML detector | `MLAnomalyDetector` |
| `ensemble.py` | Stacking meta-learner | `EnsembleStacker`, `TimeWindowEnsemble` |
| `online.py` | Online learning | `OnlineLearner`, `ADWINDriftDetector`, `ReservoirBuffer`, `ActiveLearner` |
| `drift.py` | Drift detection | `psi()`, `TemporalBiasDetector` |
| `robustness.py` | Adversarial testing | `fgsm_evasion_test()` |
| `deep_features.py` | Neural features | `EventAutoencoder`, `TemporalCNN`, `SequencePatternDetector` |
| `cross_stream.py` | Attack sequences | `AttackSequenceDetector` |
| `attack_path.py` | Path prediction | `AttackPathPredictor`, `AttackPath`, `AttackStep` |
| `insider_threat.py` | Insider detection | `InsiderThreatDetector`, `InsiderThreatScore` |
| `ueba.py` | User profiling | `UEBAEngine`, `UserBaseline` |
| `monitoring.py` | Production metrics | `ModelMonitor`, `ModelMetrics` |
| `synthetic.py` | Data generation | `generate_synthetic_dataset()`, `generate_for_ml_training()` |
| `bootstrap.py` | Cold-start model | `build_bootstrap_model()` |
| `dataset_100k.py` | 100K dataset | `build_barqaq_dataset_100k()` |
| `dataset_import.py` | External import | `ImportManager`, `ImportTask` |
| `tasks.py` | Background training | `train_in_background()`, `check_online_update()` |
| `federated.py` | Multi-org learning | `FederatedAggregator`, `FederatedClient` |
| `retention.py` | Data lifecycle | `MLDataRetention`, `RetentionPolicy` |
| `community_rules.py` | Rule contributions | `CommunityRuleManager`, `RuleValidator` |
| `remediation.py` | FN analysis | `RemediationEngine` |
| `comparison.py` | SOC comparison | `SOCComparison`, `PLATFORM_PROFILES` |
| `public_datasets.py` | Benchmarks | `CICIDSAdapter`, `UNSWNB15Adapter` |
| `explain.py` | Explainability | `explain_alert()`, `explain_event()` |

## Support

- **Documentation:** `/docs/`
- **API Reference:** `/api/docs` (Swagger UI)
- **Issues:** https://github.com/natahanjr/BARAQ/issues
