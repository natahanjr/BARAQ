# BARAQ Production Deployment — Windows Server, LAN, 50–200 Endpoints

**Scenario:** Replace Splunk with BARAQ as the company SOC.
**Server:** This Windows machine (on-prem).
**Collectors:** BARAQ agents only (no Splunk forwarders).
**Scale:** 50–200 endpoints.
**Network:** Analysts + agents on the same LAN.
**TLS:** Self-signed certificate (upgrade to internal CA later).

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  THIS WINDOWS SERVER                                     │
│  BARAQ Backend :8443 (HTTPS)  +  PostgreSQL :55432       │
│  Dashboard, Detection, Alerting, ML, SOAR                │
└────────────────────────┬─────────────────────────────────┘
                         │  POST /api/ingest (X-Agent-Key)
        ┌────────────────┼────────────────┬───────────────┐
        ▼                ▼                ▼               ▼
   ┌─────────┐      ┌─────────┐     ┌─────────┐     ┌─────────┐
   │ Agent   │      │ Agent   │     │ Agent   │     │ Agent   │
   │ srv-01  │      │ ws-01   │     │ ws-02   │ ... │ ws-200  │
   └─────────┘      └─────────┘     └─────────┘     └─────────┘
```

**What analysts get:** one dashboard at `https://<server-ip>:8443` — alerts, investigations, fleet health, threat intel.

---

## Phase 0 — Prerequisites (one-time)

| Item | Status / Action |
|------|-----------------|
| Python 3.12+ | ✅ required (`venv\`) |
| Node.js 22+ | ✅ for frontend build |
| PostgreSQL | ✅ service `BaraqPG` running on `:55432` |
| Firewall ports | ⬜ open **8443** inbound (Domain+Private only) |
| Self-signed cert | ⬜ generate if missing |
| Disk (logs+DB) | ⬜ ≥ 50 GB free recommended |
| RAM | ⬜ ≥ 8 GB (16 GB for 200 endpoints) |

### 0.1 Open firewall (run as Admin)

```powershell
# HTTPS only — agents and analysts use 8443
New-NetFirewallRule -DisplayName "BARAQ SOC (HTTPS)" `
  -Direction Inbound -Protocol TCP -LocalPort 8443 `
  -Action Allow -Profile Domain,Private

# Optional: HTTP for initial bootstrap before TLS is confirmed
# New-NetFirewallRule -DisplayName "BARAQ SOC (HTTP)" `
#   -Direction Inbound -Protocol TCP -LocalPort 8001 `
#   -Action Allow -Profile Domain,Private
```

**Do NOT open 5432 (Postgres) or 5173 (dev) to the LAN.**

### 0.2 Generate self-signed certificate

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\gen_cert.ps1
```

Output: `certs\baraq.crt` + `certs\baraq.key` (SANs include this machine's LAN IPs).

**Every analyst browser** must trust it once:

```powershell
# On each analyst workstation (no admin needed for CurrentUser):
powershell -NoProfile -ExecutionPolicy Bypass -File \\SERVER\BARAQ\scripts\import_cert.ps1
# Or machine-wide (admin):
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\import_cert.ps1 -Machine
```

---

## Phase 1 — Server hardening & start

### 1.1 Environment

Copy and edit `.env`:

```powershell
Copy-Item .env.example .env
notepad .env
```

**Minimum production settings in `.env`:**

```ini
BARAQ_ENV=production
BARAQ_TLS=1
BARAQ_TLS_CERT=certs/baraq.crt
BARAQ_TLS_KEY=certs/baraq.key

# Alert channels (fill what you have — at least one)
BARAQ_WEBHOOK_URL=            # Slack/Teams incoming webhook
BARAQ_SMTP_HOST=              # e.g. smtp.office365.com
BARAQ_SMTP_PORT=587
BARAQ_SMTP_STARTTLS=1
BARAQ_SMTP_USERNAME=
BARAQ_SMTP_PASSWORD=
BARAQ_SMTP_FROM=baraq@yourcompany.com
BARAQ_SMTP_TO=soc@yourcompany.com,analyst@yourcompany.com
BARAQ_NOTIFY_MIN_SEVERITY=high

# Scale for 50-200 endpoints
BARAQ_INCREMENTAL_COLLECTION=1
BARAQ_INTERVAL=15
BARAQ_AGENT_STALE_SECONDS=300
BARAQ_AGENT_OFFLINE_SECONDS=3600

# v2 stack on
BARAQ_TELEMETRY_V2=1
BARAQ_ALERTS_V2=1
BARAQ_CORRELATION=1
BARAQ_RISK=1
BARAQ_BEHAVIOR_GROUPS=1
BARAQ_V2_ENGINES_ALLOW_PROD=0
```

### 1.2 Install as Windows service (survives reboot)

```powershell
# Elevated PowerShell:
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 install -Lan
```

- Prefers **NSSM** (auto-restart). Falls back to Task Scheduler AtLogon.
- `-Lan` binds `0.0.0.0` so agents can reach it.

### 1.3 Verify server

```powershell
# From this server:
Invoke-WebRequest https://127.0.0.1:8443/api/health -SkipCertificateCheck

# From another LAN machine (after cert import):
Invoke-WebRequest https://YOUR-SERVER-IP:8443/api/health
```

Expected: `200` + JSON health payload.

**Dashboard:** `https://YOUR-SERVER-IP:8443`  
**Login:** `admin` / password from `.env` (`BARAQ_ADMIN_PASSWORD`) — **change on first login**.

---

## Phase 2 — Provision the agent fleet (50–200 hosts)

### 2.1 Define your departments/hosts

Edit or create a fleet CSV/JSON. Example for 60 endpoints across 4 depts:

`agent_configs\company-fleet.json`:

```json
{
  "server": "https://192.168.1.7:8443",
  "orgs": {
    "it":       { "name": "IT",           "hosts": ["srv-it-01", "ws-it-01", "ws-it-02"] },
    "finance":  { "name": "Finance",      "hosts": ["ws-fin-01", "ws-fin-02"] },
    "hr":       { "name": "HR",           "hosts": ["ws-hr-01"] },
    "ops":      { "name": "Operations",   "hosts": ["ws-ops-01", "ws-ops-02"] }
  }
}
```

> **Replace host names with your real asset names.** For 200 hosts, list them all — or use ranges (script expands `ws-01..ws-50`).

### 2.2 Batch-provision keys (server side)

```powershell
# Generates vault keys + per-host install commands, writes manifest:
venv\Scripts\python scripts\provision_fleet.py `
  --fleet agent_configs\company-fleet.json `
  --server https://192.168.1.7:8443 `
  --tls-cert certs\baraq.crt
```

Output: `agent_configs\company-fleet-manifest.json` with one install command per host.

**Restart the BARAQ service** so new keys load:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 fix
# or restart via services.msc → BARAQ → Restart
```

### 2.3 Distribute installers to endpoints

**Option A — Network share (recommended):**

```powershell
# On server, create share:
New-SmbShare -Name "BARAQ-Deploy" -Path "F:\My Project\Baraq\scripts" -FullAccess "Domain Admins" -ReadAccess "Domain Users"

# Copy agent + cert to share:
Copy-Item scripts\agent.py, scripts\install_agent.ps1, certs\baraq.crt \\SERVER\BARAQ-Deploy\
```

**Option B — Push via GPO / SCCM / Intune:** deploy `install_agent.ps1` + `agent.py` as a startup script.

**Option C — Manual one-liner per host** (from manifest):

```powershell
# Example from manifest (run ON the target workstation):
powershell -ExecutionPolicy Bypass -File \\SERVER\BARAQ-Deploy\install_agent.ps1 `
  -Server https://192.168.1.7:8443 `
  -Key "baraq-agent-xxxxx" `
  -Org finance `
  -Interval 15
```

### 2.4 Verify fleet

1. Dashboard → **System → Connected Endpoints** (or `GET /api/endpoints`).
2. Each host should show `health: ok` and growing `records_total`.
3. First ingest within ~15–30 s of agent start.

**Target after 1 hour:** ≥ 90% of endpoints `ok`, zero `offline`.

---

## Phase 3 — Cutover from Splunk

Run **parallel for 1–2 weeks** (Splunk + BARAQ both collecting):

| Day | Action |
|-----|--------|
| 1–3 | Deploy agents to **IT + critical servers** first. Validate detections fire. |
| 4–7 | Expand to Finance, HR, Ops. Tune false positives (Alerts → Suppress). |
| 8–14 | Full fleet green. Analysts triage BARAQ alerts daily. |
| 15+ | **Decommission Splunk forwarders** host-by-host after BARAQ shows `ok` for 72 h. |

### Detection validation (do this before killing Splunk)

```powershell
# Trigger a known detection on a test host (safe):
# - Failed RDP burst → brute_force rule
# - Encoded PowerShell → suspicious_powershell rule
# Confirm alert appears in dashboard + webhook/email within 60 s.
```

---

## Phase 4 — Alerting verification

1. Set `BARAQ_WEBHOOK_URL` and/or `BARAQ_SMTP_*` in `.env`.
2. Restart service.
3. Check health: `GET /api/system/notifications/health` (admin API key).
4. Fire a test high-severity alert (or wait for a real one).
5. Confirm delivery to Slack/Teams/email.

**Fallback:** failed notifications land in `NOTIFY_FALLBACK_DIR` (default `logs\notify-fallback\`) — nothing is silently dropped.

---

## Phase 5 — Daily operations

| Task | How |
|------|-----|
| Review alerts | Dashboard → Alerts (filter severity ≥ high) |
| Acknowledge / resolve | Alert detail → Status |
| Fleet health | System → Endpoints (stale/offline = investigate) |
| Backup DB | `scripts\db_backup.py backup --keep 14` (schedule daily 03:00) |
| Rotate agent keys | `scripts\provision_agent.py revoke <id>` then re-add |
| Update agents | Queue `update_agent` command from Endpoints view |
| ML retrain | Automatic (stale model > 5 min triggers) |

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Agents can't connect | Check firewall 8443, cert import, `https://` not `http://` |
| `CERTIFICATE_VERIFY_FAILED` on server logs | Outbound threat-intel SSL — set corporate proxy env or fix CA store |
| Endpoint shows `offline` | Agent task not running → re-run `install_agent.ps1` |
| No alerts | Check `NOTIFY_MIN_SEVERITY`, webhook/SMTP in `.env`, restart |
| High CPU on server | Reduce `BARAQ_INTERVAL`, ensure `BARAQ_INCREMENTAL_COLLECTION=1` |
| Service won't start | `scripts\install_service.ps1 status` / `fix`; check `logs\nssm.err.log` |

---

## Rollback

Splunk still running during Phase 3 — if BARAQ fails:

1. Leave Splunk forwarders alone (never removed until Day 15+).
2. `scripts\install_service.ps1 uninstall` stops BARAQ service.
3. Agents can be removed: `install_agent.ps1 -Uninstall` per host.

---

## Appendix — Quick command sheet

```powershell
# --- Server ---
scripts\install_service.ps1 status
scripts\install_service.ps1 install -Lan    # first-time
scripts\gen_cert.ps1                        # TLS cert
scripts\import_cert.ps1 -Machine            # trust on server

# --- Fleet ---
venv\Scripts\python scripts\provision_fleet.py --fleet agent_configs\company-fleet.json --server https://IP:8443 --tls-cert certs\baraq.crt
venv\Scripts\python scripts\provision_agent.py list
venv\Scripts\python scripts\provision_agent.py revoke ws-old-01

# --- Health ---
Invoke-WebRequest https://127.0.0.1:8443/api/health -SkipCertificateCheck
Invoke-WebRequest https://127.0.0.1:8443/api/endpoints -Headers @{"X-API-Key"="..."} -SkipCertificateCheck
```

---

**Document owner:** SOC lead  
**Last updated:** 2026-09-24  
**Related:** `docs\agent-deployment.md`, `docs\tls_https.md`, `docs\security_hardening.md`, `docs\backup_restore.md`
