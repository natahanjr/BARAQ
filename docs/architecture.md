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

### Automation (SOAR)
- `GET /api/automation/playbooks` - List playbooks
- `POST /api/automation/playbooks` - Create playbook
- `PATCH /api/automation/playbooks/{id}` - Update playbook
- `DELETE /api/automation/playbooks/{id}` - Delete playbook
- `POST /api/automation/playbooks/{id}/test` - Dry-run against an alert
- `POST /api/automation/playbooks/{id}/run` - Execute now (admin)
- `GET /api/automation/runs` - Execution history (org-scoped)
- `GET /api/automation/runs/{id}` - One run in full: run, playbook + triggers, alert, per-action results
- `GET /api/automation/preview?alert_id=` - Which playbooks would fire

**Playbooks fire automatically** when a matching alert is created — the pipeline
invokes the engine directly, so an analyst does not have to press "Run". A
fresh deployment ships **no playbooks**, so nothing fires until you seed some
(`scripts/seed_playbooks.py`). A run is recorded per playbook with the
per-action status and detail, and is visible under Automation → Execution
History. While `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=0` (the default)
containment actions are simulated and the run records `SIMULATED <action>`.

Starter playbooks: `venv\Scripts\python scripts\seed_playbooks.py`
(idempotent; `--with-soar` adds containment playbooks, which stay disabled).

## Security Model

### Authentication
- HMAC-signed access tokens with a short expiry and a separate refresh token
- **Strictly typed tokens**: an MFA challenge or a password-reset token is not
  an access token, and a token carrying no recognised type is rejected
- Session invalidation on password change (`sessions_valid_after` epoch),
  revocation, and logout that prunes outstanding sessions
- MFA support (TOTP)
- SSO integration (LDAP, OIDC). Roles are derived from group membership
  intersected with the local `LDAP_ADMIN_GROUPS` allowlist — never from a role
  claim in the token — and re-synced on every login
- API key authentication (legacy shared keys; rejected in production)

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
