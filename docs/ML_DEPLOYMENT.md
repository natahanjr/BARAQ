# BARAQ ML Deployment Guide

## Prerequisites

- Python 3.13+
- PostgreSQL 14+
- Node.js 18+ (for frontend)
- 4GB+ RAM recommended
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

**Optional Deep Learning:**
```bash
pip install torch torchvision  # For autoencoder features
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
```

## ML System Setup

### Initial Training

```bash
# Via API
curl -X POST http://localhost:8000/api/system/ml/train?async_mode=false

# Via CLI
python -c "from backend.ml.anomaly import get_detector; get_detector().train()"
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
    depends_on:
      - db

  db:
    image: postgres:16
    environment:
      - POSTGRES_DB=baraq
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### Systemd Service

```ini
[Unit]
Description=BARAQ Security Platform
After=network.target postgresql.service

[Service]
Type=simple
user=baraq
working-directory=/opt/baraq
ExecStart=/opt/baraq/venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
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
```

### Metrics (Prometheus)

```bash
# Metrics endpoint
curl http://localhost:8000/metrics

# Key ML metrics:
# - ml_model_state (0=CRITICAL, 1=WARNING, 2=HEALTHY)
# - ml_scored_events_total
# - ml_training_duration_seconds
# - ml_drift_psi{stream="login|process|network"}
```

### Logging

```bash
# ML subsystem logs
tail -f /var/log/baraq/ml.log

# Or via journalctl
journalctl -u baraq -f
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
```

### High Memory Usage

```bash
# Check model size
ls -lh backend/ml/model.bundle*

# Reduce model complexity
# Edit config.py:
# ML_MIN_SAMPLES = 20  # Increase minimum samples
```

## Backup and Recovery

### Backup Models

```bash
# Backup model bundle
cp backend/ml/model.bundle /backup/model.bundle.$(date +%Y%m%d)

# Backup metadata
cp backend/ml/model_meta.json /backup/model_meta.$(date +%Y%m%d).json
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

## Security Hardening

### Model Security

```bash
# Verify model integrity
sha256sum backend/ml/model.bundle

# Set restrictive permissions
chmod 600 backend/ml/model.bundle
chmod 600 backend/ml/model_meta.json
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

## Support

- **Documentation:** `/docs/`
- **API Reference:** `/api/docs` (Swagger UI)
- **Issues:** https://github.com/natahanjr/BARAQ/issues
