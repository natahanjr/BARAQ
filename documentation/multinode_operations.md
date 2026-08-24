# Multi-node operation (roadmap 3.1)

BARAQ scales from a single all-in-one process to a multi-node deployment
with zero code changes. Every knob below is a `BARAQ_*` environment
variable.

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
