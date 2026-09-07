# BARAQ Architecture

## System Overview

BARAQ is an Intelligent Lightweight Security Operations Center (SOC) platform for real-time Windows threat detection and incident analysis.

### Core Components

```
┌─────────────────────────────────────────────────────────┐
│                    BARAQ Platform                       │
├──────────────┬──────────────┬──────────────┬───────────┤
│   Frontend   │   Backend    │  PostgreSQL  │  Windows  │
│  React/Vite  │   FastAPI    │    Database  │   Agent   │
└──────────────┴──────────────┴──────────────┴───────────┘
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | React 19, Vite 8, Tailwind 4 | SPA dashboard |
| Backend | FastAPI, Python 3.11+ | REST API |
| Database | PostgreSQL 15+ | Data storage |
| Agent | PowerShell | Windows telemetry |

## Data Flow

```
Windows Endpoints
       │
       ▼
  BARAQ Agent (PowerShell)
       │
       ▼
  Backend API (FastAPI)
       │
       ├─► Alert Processing
       ├─► ML Detection
       ├─► Correlation Engine
       ├─► UEBA Analytics
       └─► Incident Response
              │
              ▼
        PostgreSQL Database
              │
              ▼
       Frontend Dashboard
```

## Database Schema

### Core Tables

- `users` - User accounts and roles
- `alerts` - Security alerts
- `incidents` - Incident tracking
- `behavior_groups` - Alert clustering
- `correlation_findings` - Correlation results
- `endpoints` - Monitored endpoints
- `detection_rules` - Custom detection rules

### Audit Tables

- `audit_log` - System audit trail
- `audit_events` - Detailed event logging

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/register` - User registration
- `GET /api/auth/audit/export` - Audit log export

### Alerts
- `GET /api/alerts` - List alerts
- `POST /api/alerts/{id}/status` - Update alert status
- `POST /api/alerts/{id}/verdict` - Submit verdict

### Incidents
- `GET /api/incidents` - List incidents
- `POST /api/incidents` - Create incident
- `PUT /api/incidents/{id}` - Update incident

### Correlation
- `GET /api/correlations/rules` - List correlation rules
- `GET /api/correlations/{id}` - Correlation details
- `GET /api/correlations/{id}/groups` - Related groups

### Automation
- `GET /api/automation/playbooks` - List playbooks
- `POST /api/automation/playbooks` - Create playbook
- `POST /api/automation/run` - Execute playbook

## Security Model

### Authentication
- JWT tokens with configurable expiration
- MFA support (TOTP)
- SSO integration (OAuth2/SAML)
- API key authentication

### Authorization
- Role-based access control (RBAC)
- Admin, analyst, viewer roles
- Endpoint-level permissions

### Encryption
- DPAPI vault for secrets
- TLS for transit encryption
- PostgreSQL SSL connections

## Deployment

### Development
```bash
# Backend
cd backend
pip install -r requirements.txt
python -m uvicorn backend.main:app --reload --port 8001

# Frontend
cd frontend
npm install
npm run dev
```

### Production
```bash
# Docker
docker build -t baraq .
docker run -p 8001:8001 baraq

# Or native
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

## Monitoring

### Health Checks
- `GET /api/system/health` - System health
- `GET /api/system/status` - Detailed status

### Metrics
- Prometheus metrics at `/metrics`
- OpenTelemetry traces (optional)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BARAQ_ENV` | `development` | Environment mode |
| `BARAQ_DB_URL` | - | PostgreSQL connection |
| `BARAQ_JWT_SECRET` | - | JWT signing key |
| `BARAQ_API_KEYS` | - | API authentication keys |

### Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `TELEMETRY_V2_ENABLED` | `true` | New telemetry system |
| `ALERTS_V2_ENABLED` | `true` | New alerts API |
| `CORRELATION_ENABLED` | `true` | Correlation engine |
| `RISK_ENABLED` | `true` | Risk scoring |
