# SentinelSOC - Agent Fleet

Remote hosts run `scripts/agent.py` (a small, dependency-light telemetry
shipper) and authenticate to the central server with a per-host key. The
server attributes every record to the reporting agent, runs the full
detection pipeline, and lets analysts push mitigation commands back to the
host.

## Architecture

```
+------------------+   POST /api/ingest            +----------------------+
|  host agent      | -- X-Agent-Key: <key> ------> |  central SentinelSOC |
|  scripts/agent.py|                               |  - validates key     |
|                  | <--- GET /api/commands/pending|  - runs pipeline     |
|  executes        | --- POST /api/commands/{id}/result (block_ip,        |
|  command locally |      kill_process, quarantine, isolate, ...)         |
+------------------+                               +----------------------+
```

- Agent keys are a JSON map `{"<key>": "<agent-id>"}` stored encrypted in
  the app vault (`secrets.dat`, key `SENTINEL_AGENT_KEYS`).
- `/api/endpoints` lists the fleet with per-host record/event/alert volume
  and last-seen. The dashboard Endpoints view renders this live.
- Command flow: admin queues a command for an agent; the agent polls
  `GET /api/commands/pending` every cycle, executes, and reports back.
- Keys are shared with the agent in cleartext at provisioning time only and
  must be treated as secrets afterwards.

## Provision a host (on the server)

```bash
venv\Scripts\python scripts\provision_agent.py add edge-host-1 https://soc.example.com:8443
```

This generates a key, writes it to the vault, and saves the agent's launch
config to `agent_configs/edge-host-1.json`. **Restart the SentinelSOC
service** afterwards so the new key is loaded (keys are read at startup).

Copy the shipper to the host and run:

```bash
python scripts/agent.py --server https://soc.example.com:8443 --key "<key>" --interval 15
```

Recommended fleet ops:

- Run the agent as a scheduled task at startup (or a service) so it always
  reports; `--interval 15` is a good default for the 2-3 host reference
  deployment.
- Reach the server over HTTPS (reverse proxy) - the ingest channel is
  bearer-key authenticated but is not encrypted in transit by itself.
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
  from `SENTINEL_AGENT_KEYS` and any further ingest from it returns 401.
- The endpoint row (historical volume) is retained after revoke; only the
  credential is removed.

## Notes & limits

- Ingest records must carry a numeric `event_id`, `source`, and
  `timestamp`; malformed records are rejected with 400 (not a 500) so one
  bad host cannot wedge the API.
- Records per ingest capped at 2000; agent collections are small in
  practice.
- The dev default key `sentinel-agent-dev` (agent-id `agent-dev`) is baked
  into development builds; production builds drop it via the G3 gate.