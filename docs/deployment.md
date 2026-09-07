# BARAQ Deployment Guide

## Prerequisites

### System Requirements

- **OS:** Windows 10/11 or Windows Server 2019+
- **Python:** 3.11 or higher
- **Node.js:** 18 or higher
- **PostgreSQL:** 15 or higher
- **RAM:** 4GB minimum, 8GB recommended
- **Disk:** 10GB minimum

### Required Software

1. Python 3.11+
2. Node.js 18+
3. PostgreSQL 15+
4. Git

## Development Deployment

### 1. Clone Repository

```bash
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ
```

### 2. Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 3. Database Setup

```bash
# Create PostgreSQL database
psql -U postgres -c "CREATE DATABASE baraq;"

# Copy environment file
copy .env.example .env

# Edit .env with your database credentials
```

### 4. Start Services

```bash
# Terminal 1: Backend
python -m uvicorn backend.main:app --reload --port 8001

# Terminal 2: Frontend
cd frontend
npm install
npm run dev
```

### 5. Access Application

- **Frontend:** http://localhost:5173
- **Backend API:** http://localhost:8001
- **API Docs:** http://localhost:8001/docs

## Production Deployment

### Option 1: Native Deployment

#### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

#### 2. Configure Environment

```bash
# Set environment variables
set BARAQ_ENV=production
set BARAQ_DB_URL=postgresql://user:pass@localhost:5432/baraq
set BARAQ_JWT_SECRET=your-secure-secret-key
```

#### 3. Initialize Database

```bash
python -c "from backend.database.connection import init_db; init_db()"
```

#### 4. Start Service

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

### Option 2: Docker Deployment

#### 1. Build Image

```bash
docker build -t baraq .
```

#### 2. Run Container

```bash
docker run -d \
  --name baraq \
  -p 8001:8001 \
  -e BARAQ_DB_URL=postgresql://user:pass@host:5432/baraq \
  -e BARAQ_JWT_SECRET=your-secret \
  baraq
```

### Option 3: Docker Compose

```yaml
version: '3.8'
services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: baraq
      POSTGRES_USER: baraq
      POSTGRES_PASSWORD: your-password
    volumes:
      - pgdata:/var/lib/postgresql/data

  api:
    build: .
    ports:
      - "8001:8001"
    environment:
      BARAQ_DB_URL: postgresql://baraq:your-password@db:5432/baraq
    depends_on:
      - db

volumes:
  pgdata:
```

## Windows Agent Deployment

### 1. Install Agent

```powershell
# Copy agent files to target endpoint
Copy-Item -Path "\\server\share\agent" -Destination "C:\Program Files\BARAQ Agent" -Recurse

# Register agent
cd "C:\Program Files\BARAQ Agent"
.\Install-Agent.ps1 -ServerUrl "http://your-server:8001"
```

### 2. Configure Agent

```powershell
# Edit agent configuration
notepad "C:\Program Files\BARAQ Agent\config.json"
```

### 3. Start Agent Service

```powershell
# Install as Windows Service
Install-Service -Name "BARAQAgent" -BinaryPath "C:\Program Files\BARAQ Agent\agent.exe"

# Start service
Start-Service -Name "BARAQAgent"
```

## Service Management

### Windows Services

```powershell
# Check status
Get-Service -Name "BARAQ*"

# Start/Stop
Start-Service -Name "BARAQAgent"
Stop-Service -Name "BARAQAgent"

# Restart
Restart-Service -Name "BARAQAgent"
```

### Batch Scripts

```bash
# Start all services
start_services.bat

# Stop all services
stop_services.bat
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BARAQ_ENV` | Environment mode | `development` |
| `BARAQ_DB_URL` | PostgreSQL URL | - |
| `BARAQ_JWT_SECRET` | JWT signing key | - |
| `BARAQ_API_KEYS` | API keys | - |
| `BARAQ_ALLOW_DEV_KEYS` | Allow dev keys | `0` |

### Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `TELEMETRY_V2_ENABLED` | New telemetry | `true` |
| `ALERTS_V2_ENABLED` | New alerts API | `true` |
| `CORRELATION_ENABLED` | Correlation engine | `true` |
| `RISK_ENABLED` | Risk scoring | `true` |

## Monitoring

### Health Checks

```bash
# System health
curl http://localhost:8001/api/system/health

# Detailed status
curl http://localhost:8001/api/system/status
```

### Logs

```bash
# Backend logs
tail -f logs/baraq.log

# Windows Event Log
Get-EventLog -LogName Application -Source "BARAQ*"
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check PostgreSQL is running
   - Verify credentials in `.env`
   - Check firewall rules

2. **Port Already in Use**
   - Change port in configuration
   - Kill process using the port

3. **Permission Denied**
   - Run as Administrator
   - Check file permissions

### Debug Mode

```bash
# Enable debug logging
set BARAQ_ENV=development
set LOG_LEVEL=DEBUG
```

## Backup and Restore

### Database Backup

```bash
pg_dump -U postgres baraq > backup.sql
```

### Database Restore

```bash
psql -U postgres baraq < backup.sql
```

## Security Notes

1. **Never commit secrets** to version control
2. **Use DPAPI vault** for production secrets
3. **Enable HTTPS** in production
4. **Rotate API keys** regularly
5. **Monitor audit logs** for suspicious activity
