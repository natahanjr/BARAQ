# BARAQ - Agent Fleet

Remote hosts run `scripts/agent.py` (a small, dependency-light telemetry
shipper) and authenticate to the central server with a per-host key. The
server attributes every record to the reporting agent, runs the full
detection pipeline, and lets analysts push mitigation commands back to the
host.

## Architecture

```
+------------------+   POST /api/ingest            +----------------------+
|  host agent      | -- X-Agent-Key: <key> ------> |  central BARAQ |
|  scripts/agent.py|                               |  - validates key     |
|                  | <--- GET /api/commands/pending|  - runs pipeline     |
|  executes        | --- POST /api/commands/{id}/result (block_ip,        |
|  command locally |      kill_process, quarantine, isolate, ...)         |
+------------------+                               +----------------------+
```

- Agent keys are a JSON map `{"<key>": "<agent-id>"}` stored encrypted in
  the app vault (`secrets.dat`, key `BARAQ_AGENT_KEYS`).
- `/api/endpoints` lists the fleet with per-host record/event/alert volume
  and last-seen. The dashboard Endpoints view renders this live.
- Command flow: admin queues a command for an agent; the agent polls
  `GET /api/commands/pending` every cycle, executes, and reports back.
- Keys are shared with the agent in cleartext at provisioning time only and
  must be treated as secrets afterwards.

## Provision a host (on the server)

```bash
venv\Scripts\python scripts\provision_agent.py add edge-host-1 https://soc.example.com:8443
venv\Scripts\python scripts\provision_agent.py add ws-eng-02 https://soc.example.com:8443 --org eng --tls-cert certs\baraq.crt
```

This generates a key, writes it to the vault (and, with `--org`, maps the
agent to a tenant in `BARAQ_AGENT_ORGS`), and saves the agent's launch
config to `agent_configs/edge-host-1.json`. **Restart the BARAQ
service** afterwards so the new key and org mapping are loaded (both are
read at startup).

Copy the shipper to the host and run:

```bash
python scripts/agent.py --server https://soc.example.com:8443 --key "<key>" --interval 15 --tls-ca certs/baraq.crt
```

For multi-campus fleets, `scripts/provision_university.py` batches a whole
org at once and emits a manifest with one launch line per host — see
`documentation/deployment_guide.md`.

Recommended fleet ops:

- Run the agent as a scheduled task at startup (or a service) so it always
  reports; `--interval 15` is a good default for the reference deployment.
- Serve the console over HTTPS (built-in: `start.bat secure lan`, port
  8443); agents must pin the server certificate with `--tls-ca` so ingest
  is encrypted and verified end-to-end.
- Validate from the dashboard: Command Center > Endpoints shows the new
  host with `last_seen` refreshing every interval; volume counters increment
  per cycle. You can also hit `GET /api/endpoints` directly.

## Verify a host end-to-end

1. `GET /api/endpoints` - the host appears with `records_total` growing.
2. Queue a test command (Command Center > Endpoints > the host, or
   `POST /api/endpoints/<id>/commands` with `{"action":"block_ip",
   "target":"198.51.100.99"}`) and confirm it flips to `success`/`failed`
   after the agent's next cycle.
3. Push a real event and watch the pipeline: alert pages / `/api/alerts`.

## Rotate / revoke

```bash
venv\Scripts\python scripts\provision_agent.py list        # what is registered
venv\Scripts\python scripts\provision_agent.py revoke edge-host-1
```

- Rotation: provision a new key under the same agent-id after revoking the
  old one; update the host's launch command, then restart the server.
- Revocation is immediate on the next server restart - the key is dropped
  from `BARAQ_AGENT_KEYS` and any further ingest from it returns 401.
- The endpoint row (historical volume) is retained after revoke; only the
  credential is removed.

## Fleet health, grouping and auto-update (roadmap 3.4)

Every ingest doubles as a heartbeat. Agents report `agent_version` and
`os_info` (set automatically by `scripts/agent.py`); the server computes a
health status on read:

| Status   | Meaning (since last ingest)                       |
|----------|---------------------------------------------------|
| `ok`     | within `BARAQ_AGENT_STALE_SECONDS` (default 300)  |
| `stale`  | past stale window, within `BARAQ_AGENT_OFFLINE_SECONDS` (3600) |
| `offline`| past the offline window                           |

Fleet dashboard (admin + analyst, tenant-scoped):

```http
GET /api/endpoints/overview     # health buckets, by-org/version/tag, stale+offline lists
GET /api/endpoints?tag=web      # filtered fleet list (also ?health=stale)
POST /api/endpoints/<agent>/tags  {"tags": "dmz,web"}     # admin - grouping
```

Grouping: comma-separated tags per agent drive the `by_tag` breakdown and
`?tag=` filter, so operators can treat "all web servers" or "all DMZ hosts"
as one unit.

Auto-update: queue an update the same way as any command:

```http
POST /api/endpoints/<agent>/commands
{"action": "update_agent", "target": "2.1.0", "note": "rollout batch 1"}
```

The agent executes it on its next poll: `scripts/agent_updater.ps1` swaps
the agent files (downloads `baraq-agent-v<VERSION>.zip` from
`BARAQ_UPDATE_URL` if set; otherwise records the rollout target in
`agent.config.json`) and restarts the scheduled task. The fleet view shows
`update_status = pending` during rollout and `current` after the agent
reports success; failed commands bump `errors_total`.

## Notes & limits

- Ingest records must carry a numeric `event_id`, `source`, and
  `timestamp`; malformed records are rejected with 400 (not a 500) so one
  bad host cannot wedge the API.
- Records per ingest capped at 2000; agent collections are small in
  practice.
- The dev default key `baraq-agent-dev` (agent-id `agent-dev`) is baked
  into development builds; production builds drop it via the G3 gate.