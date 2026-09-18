# BARAQ Agent Deployment Guide

> **Audience:** ICT administrators deploying BARAQ agents across an institution.
> This guide walks you through installing the telemetry agent on every
> department laptop/PC so the super admin can monitor all endpoints from one
> dashboard.

---

## Table of Contents

1. [How It Works](#how-it-works)
2. [Prerequisites](#prerequisites)
3. [Two Agent Types](#two-agent-types)
4. [Quick Start (5 Minutes)](#quick-start-5-minutes)
5. [Step-by-Step Deployment](#step-by-step-deployment)
6. [Department Seeding](#department-seeding)
7. [Manual Installation](#manual-installation)
8. [Verifying Agents](#verifying-agents)
9. [Troubleshooting](#troubleshooting)
10. [Uninstalling](#uninstalling)
11. [Security Notes](#security-notes)

---

## How It Works

BARAQ uses an **agent-based architecture**:

```
┌─────────────────────────────────────────────────────┐
│               SUPER ADMIN SERVER                    │
│          BARAQ Backend (port 8001)                  │
│     Dashboard, Detection, Alerting, API             │
└────────────────────┬────────────────────────────────┘
                     │  Collects telemetry via API
        ┌────────────┼────────────┬────────────┐
        │            │            │            │
        ▼            ▼            ▼            ▼
   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
   │ Agent   │  │ Agent   │  │ Agent   │  │ Agent   │
   │ ICT PC  │  │ Library │  │ Finance │  │ Registrar│
   └─────────┘  └─────────┘  └─────────┘  └─────────┘
```

**What the agent does:**
- Reads Windows Event Logs (Security, System, PowerShell, Sysmon)
- Collects process and network connection data
- Sends everything to the BARAQ server every 15 seconds
- Runs silently in the background as a Windows Scheduled Task

**What the agent does NOT do:**
- No remote desktop / screen sharing
- No file access or modification
- No keyboard/mouse control
- Just **reads logs and sends them** to the server

---

## Prerequisites

### On the BARAQ Server
- BARAQ server running and accessible from the network
- Python 3.8+ installed
- Firewall allowing incoming connections on port 8001

### On Each Endpoint (Laptop/PC)
- Windows 10 or 11
- Network access to the BARAQ server
- Administrator privileges (for installing the scheduled task)
- **Python NOT required** (PowerShell agent works without it)

---

## Two Agent Types

BARAQ provides two agent options depending on your needs:

| Feature | PowerShell Agent (Recommended) | Python Agent (Full) |
|---|---|---|
| **File** | `agent.ps1` | `agent.py` + `install_agent.ps1` |
| **Python Required** | No | Yes (3.8+) |
| **Installation** | None — run directly | Install script + scheduled task |
| **Processes** | First 300, delta only | Full process tree with hashes |
| **Network** | TCP connections only | TCP + UDP + DNS + HTTP |
| **Event Logs** | Not collected | Security, System, PowerShell, Sysmon |
| **Registry Changes** | Not collected | Monitored |
| **Scheduled Tasks** | Not collected | Monitored |
| **USB Events** | Not collected | Monitored |
| **File Integrity** | Not collected | Monitored |
| **Background Mode** | Manual or scheduled task | Scheduled task with auto-start |
| **Best For** | Quick deployment, low-resource PCs | Full SOC visibility |

### When to Use Which

**Use PowerShell Agent when:**
- You need quick deployment (no Python install required)
- Target PCs have limited resources
- You only need process and network data
- You want to test the system before full deployment

**Use Python Agent when:**
- You need complete SOC visibility (Event Logs, Sysmon, DNS, USB, etc.)
- You want automatic persistence via scheduled task
- You need richer telemetry for ML anomaly detection
- This is a production security monitoring deployment

---

## Quick Start (5 Minutes)

If you already have the BARAQ server running, deploy to one laptop in 3 steps:

### Option A: PowerShell Agent (No Python Required)

```powershell
# On the target laptop, open PowerShell and run:
powershell -ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\agent.ps1 `
    -Server http://192.168.1.5:8001 `
    -Key "YOUR-AGENT-KEY"

# For background mode (runs until you close the window):
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\agent.ps1 -Server http://192.168.1.5:8001 -Key YOUR-AGENT-KEY" -WindowStyle Hidden
```

### Option B: Python Agent (Full Telemetry)

```powershell
# Step 1: Seed departments (on server)
cd "C:\path\to\BARAQ"
venv\Scripts\python scripts\seed_departments.py --server http://192.168.1.5:8001

# Step 2: Copy installer to network share
copy scripts\install_agent.ps1 \\SERVER\Shared\BARAQ\
copy scripts\agent.py \\SERVER\Shared\BARAQ\

# Step 3: Run on target laptop
powershell -ExecutionPolicy Bypass -File \\SERVER\Shared\BARAQ\install_agent.ps1 `
    -Server http://192.168.1.5:8001 `
    -Key "baraq-library-ws-lib-01" `
    -Org library
```

**Done!** The agent installs, registers, and starts sending data to the server.

---

## Step-by-Step Deployment

### Step 1: Seed Departments (Server Side)

The seeding script creates unique API keys for each department and host:

```powershell
# On the BARAQ server:
cd "C:\path\to\BARAQ"

# Seed ALL departments (10 departments, ~30 endpoints)
venv\Scripts\python scripts\seed_departments.py --server http://YOUR-SERVER-IP:8001

# Seed ONLY specific departments
venv\Scripts\python scripts\seed_departments.py --server http://YOUR-SERVER-IP:8001 --orgs "library,finance,registrar"

# Preview without saving (dry run)
venv\Scripts\python scripts\seed_departments.py --dry-run
```

**Output example:**

```
======================================================================
  BARAQ DEPARTMENT SEEDING MANIFEST
======================================================================
  Server: http://192.168.1.100:8001
  Departments: 10
  Total Endpoints: 30
======================================================================

  [ICT] ICT Department
  IT servers and admin workstations
  Hosts: 3
----------------------------------------------------------------------
    srv-ict-01
      Key:     baraq-ict-srv-ict-01
      Command: powershell -ExecutionPolicy Bypass -File scripts/install_agent.ps1 -Server http://192.168.1.100:8001 -Key "baraq-ict-srv-ict-01" -Org ict

    ws-ict-01
      Key:     baraq-ict-ws-ict-01
      Command: powershell -ExecutionPolicy Bypass -File scripts/install_agent.ps1 ...
```

### Step 2: Copy Agent Files to Network Share

Create a shared folder accessible by all department laptops:

```powershell
# On the server, create a shared folder
mkdir C:\BARAQ-Deploy

# Copy BOTH agent types
copy scripts\install_agent.ps1 C:\BARAQ-Deploy\
copy scripts\agent.py C:\BARAQ-Deploy\
copy scripts\agent.ps1 C:\BARAQ-Deploy\

# Share the folder (run as Administrator)
net share BARAQ-Deploy=C:\BARAQ-Deploy /GRANT:Everyone,READ
```

### Step 3: Install on Each Endpoint

**Method A: PowerShell Agent (Recommended for quick deployment)**

No installation needed — just run directly:

```powershell
# On the target laptop:
powershell -ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\agent.ps1 `
    -Server http://192.168.1.100:8001 `
    -Key "YOUR-AGENT-KEY"

# To run in background (hidden window):
Start-Process powershell -ArgumentList "-ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\agent.ps1 -Server http://192.168.1.100:8001 -Key YOUR-AGENT-KEY" -WindowStyle Hidden
```

**Method B: Python Agent (Full telemetry)**

```powershell
# On the target laptop:
powershell -ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\install_agent.ps1 `
    -Server http://192.168.1.100:8001 `
    -Key "baraq-library-ws-lib-01" `
    -Org library
```

**Method C: Manual Python Installation**

If Python is available but the installer script is not:

```powershell
# On the target laptop:
mkdir C:\BARAQAgent
copy \\SERVER\BARAQ-Deploy\agent.py C:\BARAQAgent\

# Create config file
@{
    server = "http://192.168.1.100:8001"
    key = "baraq-library-ws-lib-01"
    interval = 15
    org = "library"
} | ConvertTo-Json | Set-Content C:\BARAQAgent\agent.config.json

# Run the agent
python C:\BARAQAgent\agent.py --config C:\BARAQAgent\agent.config.json --install
```

**Method D: Group Policy (Advanced)**

For large deployments, push via Group Policy:

1. Place `install_agent.ps1` and `agent.py` on a DFS share
2. Create a GPO startup script that runs the installer
3. Use WMI to trigger on specific OUs

### Step 4: Verify in Dashboard

1. Open the BARAQ dashboard: `http://YOUR-SERVER-IP:8001`
2. Navigate to **System > Connected Endpoints**
3. You should see all deployed hosts with:
   - Status: Online (green)
   - Last Seen: within the last 15 seconds
   - Department tag
   - Record count increasing

---

## Department Seeding

### Default Department Layout

The seed script comes pre-configured with a typical institution layout:

| Department | Hosts | Description |
|---|---|---|
| ICT | 3 | Servers and admin workstations |
| Library | 4 | OPAC terminals and staff PCs |
| Finance | 4 | Accounting workstations |
| Registrar | 3 | Student records systems |
| HR | 2 | Personnel records |
| Admissions | 4 | Application processing |
| Examinations | 3 | Exam systems |
| Maintenance | 2 | Facility systems |
| Administration | 3 | Management offices |
| Vice Chancellor | 2 | Executive offices |
| **Total** | **30** | |

### Customizing Departments

Edit `scripts/seed_departments.py` to match your institution:

```python
DEFAULT_DEPARTMENTS = {
    "your-dept": {
        "name": "Your Department",
        "hosts": ["pc-01", "pc-02", "pc-03"],
        "description": "What this department does",
    },
    # Add more departments...
}
```

### Adding a New Department Later

```powershell
# Seed just the new department
venv\Scripts\python scripts\seed_departments.py --server http://YOUR-SERVER:8001 --orgs "newdept"

# The manifest shows the new hosts and their installation commands
```

---

## Manual Installation

### PowerShell Agent Command Reference

```
agent.ps1 [OPTIONS]

Options:
  -Server URL       BARAQ server URL (default: http://localhost:8001)
  -Key KEY          Agent API key for authentication (required)
  -Interval SECONDS Collection interval (default: 15)
  -Once             Send a single batch and exit (for testing)
```

### Python Agent Command Reference

```
python scripts/agent.py [OPTIONS]

Options:
  --server URL         BARAQ server URL (default: http://localhost:8001)
  --key KEY            Agent API key for authentication
  --interval SECONDS   Collection interval (default: 15)
  --config FILE        Config file path
  --log FILE           Log file path
  --tls-ca FILE        TLS certificate to pin (for HTTPS servers)
  --no-verify          Skip TLS verification (lab only)
  --install            Register as Windows Scheduled Task
  --uninstall          Remove the Scheduled Task
  --purge              Also delete config directory
  --verbose            Enable debug logging
```

---

## Verifying Agents

### Check Agent Status (Server Side)

```powershell
# List all connected endpoints
curl http://YOUR-SERVER:8001/api/endpoints

# Or use the dashboard:
# System > Connected Endpoints
```

### Check Agent Status (Client Side)

```powershell
# For Python agent - check if the scheduled task is running
Get-ScheduledTask -TaskName "BARAQ Agent"

# View the agent log
Get-Content "$env:LOCALAPPDATA\BARAQAgent\agent.log" -Tail 20

# Test connectivity to server
Invoke-WebRequest -Uri "http://YOUR-SERVER:8001/api/health" -UseBasicParsing
```

### Send a Test Command

```powershell
# From the server, queue a test command for an agent:
curl -X POST http://YOUR-SERVER:8001/api/endpoints/EP_ID/commands `
    -H "Content-Type: application/json" `
    -d '{"action":"block_ip","target":"198.51.100.99"}'
```

---

## Troubleshooting

### Agent Not Connecting

| Symptom | Cause | Fix |
|---|---|---|
| "Server unreachable" | Network/firewall | Check firewall allows port 8001 |
| "401 Unauthorized" | Wrong key | Verify key matches `seed_departments.py` output |
| "Connection refused" | Server not running | Start BARAQ server on the host |
| "No agent key provided" | Missing -Key parameter | Add `-Key YOUR-AGENT-KEY` to command |
| Agent stops after a while | Python crash | Check log: `%LOCALAPPDATA%\BARAQAgent\agent.log` |

### Common Fixes

```powershell
# Restart the Python agent
Restart-ScheduledTask -TaskName "BARAQ Agent"

# Reinstall the Python agent
python C:\BARAQAgent\agent.py --config C:\BARAQAgent\agent.config.json --install

# Check Python agent log for errors
Get-Content "$env:LOCALAPPDATA\BARAQAgent\agent.log" -Tail 50

# Test server connectivity
Test-NetConnection -ComputerName YOUR-SERVER -Port 8001
```

### Python Not Found (Python Agent Only)

```powershell
# Check Python is in PATH
python --version

# If not found, add Python to PATH:
$env:PATH += ";C:\Python312;C:\Python312\Scripts"

# Or use full path in the install command:
C:\Python312\python.exe C:\BARAQAgent\agent.py --install

# OR just use the PowerShell agent instead (no Python needed)!
```

---

## Uninstalling

### PowerShell Agent

```powershell
# Just stop the process
taskkill /F /IM powershell.exe /FI "WINDOWTITLE eq *agent.ps1*"

# Or if running as scheduled task
Unregister-ScheduledTask -TaskName "BARAQ Agent" -Confirm:$false
```

### Python Agent

```powershell
# Option 1: Use the installer with -Uninstall flag
powershell -ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\install_agent.ps1 `
    -Server http://YOUR-SERVER:8001 `
    -Key "baraq-library-ws-lib-01" `
    -Uninstall

# Option 2: Manual removal
Unregister-ScheduledTask -TaskName "BARAQ Agent" -Confirm:$false
Remove-Item -Path "$env:LOCALAPPDATA\BARAQAgent" -Recurse -Force
```

### Revoke Agent from Server

```powershell
# Revoke a single agent
venv\Scripts\python scripts\provision_agent.py revoke ws-lib-01

# Revoke an entire department
venv\Scripts\python scripts\provision_university.py revoke-org library
```

---

## Security Notes

- **Agent keys are secrets** — treat them like passwords. Never commit to git or share in plain text.
- **Use HTTPS** in production — see `docs/tls-setup.md` for TLS configuration.
- **Least privilege** — agents only read logs, they cannot modify files or execute commands (except approved mitigations like `block_ip`).
- **Network isolation** — if possible, place the BARAQ server on a management VLAN separate from user traffic.
- **Key rotation** — rotate agent keys periodically using `provision_agent.py`.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Server health check |
| `/api/ingest` | POST | Agent sends telemetry (with `X-Agent-Key` header) |
| `/api/endpoints` | GET | List all connected endpoints |
| `/api/endpoints/{id}` | GET | Get specific endpoint details |
| `/api/endpoints/{id}/commands` | POST | Queue a command for an agent |
| `/api/commands/pending` | GET | Agent polls for pending commands |
| `/api/commands/{id}/result` | POST | Agent reports command result |
| `/api/alerts` | GET | View alerts from all agents |
| `/docs` | GET | Swagger API documentation |

---

## Support

- **Dashboard:** `http://YOUR-SERVER:8001`
- **API Docs:** `http://YOUR-SERVER:8001/docs`
- **Logs:** Check `%LOCALAPPDATA%\BARAQAgent\agent.log` on each endpoint (Python agent)
- **GitHub:** https://github.com/natahanjr/BARAQ
