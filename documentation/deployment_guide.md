# SentinelSOC — Central University Deployment Guide

This guide covers the supported deployment of SentinelSOC as the central
console for a multi-tenant university consortium: one central server, several
campuses ("orgs"), analyst accounts that only see their own campus traffic,
admins that see everything, and campus agents shipping host telemetry over
HTTPS.

Reference topology: **1 central Windows server + 1..N hosts per campus**.

---

## 1. Prerequisites (central server)

| Requirement | Detail |
|-------------|--------|
| OS          | Windows 10/11 (Windows Server 2019+ recommended) |
| Python      | 3.11+ on PATH |
| Node.js     | 18+ (one-time dashboard build) |
| Network     | Inbound TCP **8443** (HTTPS) from agent hosts and analysts |
| Storage     | ~1 GB headroom + growth per fleet host (SQLite default; PostgreSQL optional via `SENTINEL_DATABASE_URL`) |

## 2. Install the central server (one time)

```powershell
start.bat secure lan
```

What this does:

- creates `venv`, installs dependencies, builds the dashboard (first run only),
- generates a self-signed TLS certificate in `certs\` (SANs = localhost + all
  LAN IPv4 addresses; rotate by deleting `certs\sentinel.thumbprint` and rerunning),
- opens TCP 8443 in the Windows Firewall (needs an admin shell),
- starts uvicorn with `--ssl-certfile certs\sentinel.crt --ssl-keyfile certs\sentinel.key`
  and serves the console at **https://<server-ip>:8443**.

HTTPS is the standard deployment path. Plain `start.bat` (http, :8001) is for
local development only — campus telemetry must never cross the network
unencrypted. For a production server, run it as a Windows service instead
(see `scripts/install_service.ps1` and `documentation/windows_service.md`).

## 3. First-run security checklist

1. **Change the admin password** — Console > Users & Audit.
2. **Create analysts** — one per campus; the user's `org` must match the
   campus org id exactly (e.g. `univ-a`).
3. **Create global admins** — for operators who must see every campus.
4. Optionally wire alerting: webhook / SMTP env vars (see README).
5. Back up `secrets.dat` and the database (see `documentation/backup_restore.md`).

## 4. Provision campuses (orgs) and agents

All agent keys are generated on the server, stored in the DPAPI vault
(`secrets.dat`), and host launch configs are written to `agent_configs\`.
Keys are shown **once** at provisioning time — distribute them over a
trusted channel and treat them as secrets.

Single host, with tenant:

```powershell
venv\Scripts\python scripts\provision_agent.py add ws-lib-01 https://soc.example.com:8443 --org univ-a --tls-cert certs\sentinel.crt
```

Whole campus at once (recommended for on-boarding a university):

```powershell
venv\Scripts\python scripts\provision_university.py setup univ-a https://soc.example.com:8443 ^
    --org-name "University A" --hosts ws-lib-01,ws-lib-02,ws-chem-04,prn-lab-07 ^
    --tls-cert certs\sentinel.crt

venv\Scripts\python scripts\provision_university.py list          # campuses + hosts
venv\Scripts\python scripts\provision_university.py revoke-org univ-a
```

The script writes `agent_configs\univ-a-manifest.json` with one launch line
per host. **Restart the SentinelSOC console** so the new keys and the org
map are loaded (`SENTINEL_AGENT_KEYS` / `SENTINEL_AGENT_ORGS` are read at
startup).

The org map is what makes isolation end-to-end: detection rules and every
view in the console only see a campus's own events and alerts, and Prometheus
metrics are labeled per campus.

## 5. Deploy the agent on each campus host

On each host: copy the server certificate `certs\sentinel.crt` from the
central server, then run the launch line from the manifest:

```bat
copy \\soc\share\sentinel.crt .\sentinel.crt
python scripts\agent.py --server https://soc.example.com:8443 --key "<host-key>" --tls-ca .\sentinel.crt --interval 15
```

Make the agent auto-start with the host (startup scheduled task or service).
`--no-verify` exists for isolated labs only.

Verify in the console: **System > Connected Endpoints** shows the host after
its first cycle (`online`, volume counters climbing), attributed to the
campus org.

## 6. Console of operations per campus

- Analysts of campus A only see campus A endpoints, alerts, events,
  incidents and dashboard numbers.
- Admins see everything and can scope the dashboard to a campus.
- Cross-org access returns 404 — it never leaks data.

## 7. Fleet monitoring (optional, Docker)

```powershell
docker compose up -d prometheus grafana
```

`deploy\grafana\dashboards\sentinel-overview.json` ships with the
**Fleet per Org** row: per-campus ingestion rates, alert counts by
org+severity, reporting hosts, open alerts. The `org` template variable
focuses the view on one campus.

## 8. Backups & lifecycle

- DB + vault backup schedule: see `documentation/backup_restore.md`.
- Cert rotation: delete `certs\sentinel.thumbprint`, re-run the server
  launcher, redistribute `sentinel.crt` to clients/agents.
- Key rotation: `revoke` the host, `add` it again, update the launch line,
  restart the service.

## 9. Troubleshooting

| Symptom | Fix |
|---------|-----|
| Analyst sees wrong (or no) data | the user's `org` must equal the campus org id |
| Agent never connects | open TCP 8443; agent must use `https://` and `--tls-ca <server cert>` |
| New key returns 401 | restart the service — keys are loaded at startup |
| Browser cert warning | import `certs\sentinel.crt` into Trusted Root on the client |
| Prometheus scrape 401 | use the bearer key from `deploy\prometheus\.my-scrape-key` |
| Agent ships nothing | check `--interval`, host collectors, agent log lines |