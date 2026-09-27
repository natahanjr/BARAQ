# Multi-node operation (READY)

BARAQ scales from a single all-in-one process to a multi-node deployment with zero code changes. The multi-node infrastructure is **READY** for production use — every knob below is a `BARAQ_*` environment variable. Single-node remains the default; no configuration is required for standalone installs.


## Quick Start

Set the BARAQ_ROLE environment variable to control which components run.
Single-node (default) needs no configuration — both API and scheduler run in
one process.

### API-only node (horizontal replica)

`powershell
# Windows
 = "api"
 = "postgresql+psycopg://baraq:pass@primary:5432/baraq"
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001

# Linux / containers
BARAQ_ROLE=api BARAQ_DATABASE_URL=postgresql+psycopg://baraq:pass@primary:5432/baraq \
  python -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
`

### Dedicated scheduler node

`powershell
# Windows
 = "scheduler"
 = "postgresql+psycopg://baraq:pass@primary:5432/baraq"
python -m backend.scheduler_service

# Linux / containers
BARAQ_ROLE=scheduler BARAQ_DATABASE_URL=postgresql+psycopg://baraq:pass@primary:5432/baraq \
  python -m backend.scheduler_service
`

### Recommended: Redis-based distributed lock

When running multiple API replicas, use Redis for the scheduler lock so
failover is instant:

`powershell
 = "redis://redis:6379/0"
 = "30"
`

### Minimum environment variables for a multi-node cluster

| Variable | API node | Scheduler node | Purpose |
|---|---|---|---|
| BARAQ_ROLE | pi | scheduler | Selects process role |
| BARAQ_DATABASE_URL | required | required | Primary Postgres connection |
| BARAQ_READONLY_DATABASE_URL | optional | — | Read replica for dashboards |
| BARAQ_REDIS_URL | recommended | recommended | Distributed lock backend |
| BARAQ_SCHEDULER_LOCK_TTL | — | optional (default 30s) | Lock heartbeat interval |
| BARAQ_CELERY | — | optional (1) | Offload long jobs to Celery |
| BARAQ_CELERY_BROKER | — | required if Celery=1 | Redis URL for Celery broker |


## Process roles

| Role | What runs | When to use |
|---|---|---|
| `all` (default) | API + scheduler thread in one process | small/standalone installs |
| `api` | API only; no scheduler, no instance lock | horizontal API replicas |
| `scheduler` | `python -m backend.scheduler_service` | dedicated scheduler node |

Run the scheduler as its own service:

```powershell
# Windows service / task
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_scheduler.ps1

# Linux / containers
python -m backend.scheduler_service
```

With `BARAQ_ROLE=api` on every API replica and one scheduler node, the API
is stateless and can scale horizontally.

## Distributed scheduler lock

Only one process may run the scheduler (two schedulers would duplicate
collection and race detection). Two lock backends:

* **PostgreSQL advisory lock** (default) - `pg_try_advisory_lock`, held for
  the process lifetime. Single-writer per database; no extra infra.
* **Redis** (`BARAQ_REDIS_URL=redis://...`) - `SET NX EX` with a heartbeat
  that re-arms the TTL (`BARAQ_SCHEDULER_LOCK_TTL`, default 30s) during
  long cycles. Recommended when the API is replicated: replicas race fairly
  for the scheduler role and failover is instant when the holder dies.

A node that loses the race keeps serving API reads - the deployment stays
up, just without a scheduler, and the next healthy node takes over.

## Read replicas

`BARAQ_READONLY_DATABASE_URL` points read-only endpoints (all
`/api/dashboard/*`) at a Postgres replica:

```
BARAQ_DATABASE_URL=postgresql+psycopg://baraq:pass@primary:5432/baraq
BARAQ_READONLY_DATABASE_URL=postgresql+psycopg://baraq:pass@replica:5432/baraq
```

Writes and detection always use the primary; dashboards offload to the
replica. Without the variable, every read falls back to the primary.

## Celery (optional)

Long jobs (ML training, reports, retention, intel refresh) can be
dispatched to a Celery worker pool instead of the scheduler thread:

```
pip install celery redis
BARAQ_CELERY=1
BARAQ_CELERY_BROKER=redis://redis:6379/0
celery -A backend.celery_app worker -Q baraq -l info
```

The app object is created lazily; BARAQ runs unchanged without Celery.

## Kubernetes

`deploy/k8s/baraq.yaml` ships:

* `baraq-api` - 2+ replicas, `BARAQ_ROLE=api`, readiness/liveness probes,
  rolling update (`maxUnavailable=0`, `maxSurge=1`).
* `baraq-scheduler` - 1 replica running the scheduler service; the
  distributed lock makes automatic failover safe.
* ConfigMap with connection settings; wire secrets via a Secret.

## Zero-downtime deploy

* Probes gate traffic: a pod only receives requests after
  `/api/system/status` answers; a failing pod is drained before restart.
* Rolling updates never take both replicas down at once.
* The scheduler uses `Recreate` - a short overlap is harmless because the
  lock guarantees a single active writer; the new pod collects from its
  incremental cursor and the DB cursor (`detection_cursor`) makes detection
  idempotent across restarts.
* On shutdown the scheduler drains (stops collection, releases the lock) so
  a peer replica can take over cleanly.


## Load Balancer Configuration

Place a load balancer in front of your API replicas. Below is an nginx
example for two BARAQ API nodes.

### nginx reverse proxy

`
ginx
upstream baraq_api {
    least_conn;
    server api-node-1:8001 max_fails=3 fail_timeout=10s;
    server api-node-2:8001 max_fails=3 fail_timeout=10s;
}

server {
    listen 443 ssl;
    server_name soc.example.com;

    ssl_certificate     /etc/baraq/tls/server.crt;
    ssl_certificate_key /etc/baraq/tls/server.key;

    location / {
        proxy_pass http://baraq_api;
        proxy_set_header Host System.Management.Automation.Internal.Host.InternalHost;
        proxy_set_header X-Real-IP ;
        proxy_set_header X-Forwarded-For ;
        proxy_set_header X-Forwarded-Proto ;

        # WebSocket support (dashboard live updates)
        proxy_http_version 1.1;
        proxy_set_header Upgrade ;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }

    # Health check — route to the node that responds first
    location = /api/health {
        proxy_pass http://baraq_api;
        proxy_connect_timeout 3s;
        proxy_read_timeout 3s;
    }
}
`

### Key points

* **Session affinity is not required** — the API is stateless with
  BARAQ_ROLE=api. Any replica can serve any request.
* **WebSocket connections** (live dashboard) are long-lived; set
  proxy_read_timeout high enough (default 86400s = 24h).
* **TLS termination** at the load balancer is recommended. BARAQ serves TLS
  natively (`BARAQ_TLS_CERT`/`BARAQ_TLS_KEY`) and refuses to start in
  production without it; offloading to the LB simplifies certificate
  management. Either way, agents must be given the certificate they should
  trust (`-TlsCert`) — with LB termination, pin the LB's certificate.
* **Health check interval:** poll /api/health every 5-10 seconds. Remove
  a node from the pool after 3 consecutive failures.
* **Reading the health check:** `checks.single_instance` reports **error** only
  when a scheduler-owning instance failed to take the lock. An api-only replica
  (`BARAQ_ROLE=api`) or a node with the scheduler disabled reports it as
  informational — that is the intended state, not a fault. Only one node
  should run the scheduler.

## Health Check Endpoints

BARAQ exposes several health and readiness endpoints. Use these in your
load balancer, Kubernetes probes, and monitoring stack.

| Endpoint | Method | Description | Use case |
|---|---|---|---|
| /api/health | GET | Liveness check — returns {"status":"ok"} | Load balancer liveness probe |
| /api/system/status | GET | Readiness check — returns DB connectivity, scheduler state | K8s readiness probe, dashboards |
| /api/system/ml/status | GET | ML model health — training state, drift metrics | Operational monitoring |

### Example probe configuration (Kubernetes)

`yaml
livenessProbe:
  httpGet:
    path: /api/health
    port: 8001
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: /api/system/status
    port: 8001
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 2
`

### Quick health check from CLI

`powershell
# Basic liveness
Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/health"

# Full system status
Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/system/status" | ConvertTo-Json -Depth 5
`

## Monitoring

When running BARAQ in a multi-node configuration, monitor these metrics
per role:

### API nodes

| Metric | What to watch | Alert threshold |
|---|---|---|
| Request rate (req/s) | Traffic load per replica | Sustained >80% capacity |
| Response latency (p50/p95/p99) | API responsiveness | p99 > 2s for >5 min |
| Error rate (4xx/5xx) | Client/server errors | 5xx > 1% over 5 min |
| Active WebSocket connections | Dashboard users | Approach ulimit -n |
| Memory (RSS) | Python process memory | > 1.5 GB sustained |
| CPU utilization | Headroom for burst | > 80% sustained |

### Scheduler node

| Metric | What to watch | Alert threshold |
|---|---|---|
| Scheduler lock status | Whether this node holds the lock | No holder for >60s |
| Collection cycle duration | Time to complete a full collection pass | > 5 min (should be < 60s) |
| Detection pipeline latency | Rules + ML processing time | > 30s per batch |
| Events processed per cycle | Throughput | Sudden drop to 0 |
| ML training queue depth | Background training jobs | > 3 pending |
| Celery worker count (if enabled) | Worker availability | 0 active workers |

### Database (PostgreSQL)

| Metric | What to watch | Alert threshold |
|---|---|---|
| Connection count | Pool exhaustion | > 80% of max_connections |
| Replication lag | Read replica freshness | > 5s |
| Disk usage | Storage headroom | > 80% |
| Query latency (p95) | Slow queries | > 500ms |

### Prometheus / OpenTelemetry

BARAQ exposes Prometheus metrics via ackend/observability.py. Scrape
endpoint:

`
GET /metrics
`

Key metric prefixes:
- araq_events_total — events ingested
- araq_alerts_total — alerts generated
- araq_detection_latency_seconds — detection pipeline latency
- araq_ml_training_seconds — ML training duration
- araq_scheduler_lock_acquired — scheduler lock acquisition events

## Troubleshooting

### API replicas cannot connect to the scheduler

**Symptoms:** Dashboards show stale data; alerts stop appearing.

**Cause:** All API nodes are running with BARAQ_ROLE=api and no
scheduler is running.

**Fix:** Ensure exactly one node runs with BARAQ_ROLE=scheduler (or no
BARAQ_ROLE set, which runs both in one process). Check:

`powershell
Invoke-RestMethod -Uri "http://<scheduler-host>:8001/api/system/status"
# Should show "scheduler_running": true
`

### Scheduler lock not acquired

**Symptoms:** Scheduler node logs show "waiting for lock" or similar.

**Cause:** Another scheduler instance still holds the lock (previous pod
not yet terminated, or another node configured as scheduler).

**Fix:**
1. Verify no other scheduler is running: SELECT * FROM pg_locks WHERE locktype = 'advisory';
2. If using Redis, check BARAQ_REDIS_URL is correct and Redis is reachable.
3. Reduce BARAQ_SCHEDULER_LOCK_TTL (default 30s) so a dead holder's lock
   expires faster.

### Read replica lag

**Symptoms:** Dashboard data appears delayed or inconsistent.

**Fix:**
1. Check replication status: SELECT pg_is_in_recovery(); on the replica
   (should return 	rue).
2. Monitor lag: SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp()));
3. If lag is persistent, increase max_replication_slots and
   max_wal_senders on the primary.

### High memory on API nodes

**Symptoms:** API process RSS grows over time.

**Likely cause:** WebSocket connections not being closed, or large query
results cached in memory.

**Fix:**
1. Set proxy_read_timeout in nginx to close stale WebSocket connections.
2. Monitor /api/system/status memory metrics.
3. Restart API replicas periodically (rolling restart with
   maxUnavailable=0 ensures no downtime).

### Celery workers not processing jobs

**Symptoms:** ML training, report generation, or retention purge not running.

**Fix:**
1. Verify Celery is running: celery -A backend.celery_app inspect ping
2. Check broker connectivity: edis-cli -h <redis-host> ping
3. Ensure BARAQ_CELERY=1 and BARAQ_CELERY_BROKER are set on both the
   scheduler (producer) and Celery worker nodes.

### Load balancer marking nodes unhealthy

**Symptoms:** Requests return 502/504 intermittently.

**Fix:**
1. Check the health endpoint directly: curl http://<node>:8001/api/health
2. Verify the node's database connection is alive.
3. Increase health check timeout in the LB config (default 3s may be too
   tight under load).
4. Ensure proxy_connect_timeout in nginx matches the LB timeout.

