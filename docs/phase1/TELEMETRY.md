# Phase 1: Telemetry (v2, clean-room)

The v2 telemetry pipeline replaces the v1 collector/event path with a
strict, deterministic ingestion chain. It owns only telemetry: it never
creates alerts, never mutates risk, never opens incidents (boundary
enforced and tested).

## Canonical EVENT (contract v1.1)

One structure every telemetry source produces, so detection never parses
raw formats:

| Field | Meaning |
|-------|---------|
| `event_id` | Source-native id (e.g. Windows event id) |
| `timestamp` | Event time (UTC, tz-aware) |
| `event_type` | Classification: `authentication`, `process`, `network`, `event`, ... |
| `host` | Machine the event happened on |
| `user` | Account involved (or `-`) |
| `source` | Telemetry source: `windows`, `syslog`, `web`, ... |
| `destination` | Target host/IP |
| `process` | `{name, path, pid, parent, ...}` |
| `network` | `{src_ip, dst_ip, src_port, dst_port, proto}` |
| `action` | What happened (e.g. `logon_failed`) |
| `outcome` | `success` / `failure` / `""` |
| `raw_event` | Original record (audit provenance) |
| `schema_version` | Contract version (currently `1.1`) |

`facts` carries free-form extras. The fingerprint (dedup key) is computed
from source/host/user/action/ts-ms/facts/org and is unchanged by the
structured fields.

## Pipeline

```text
raw records -> normalize -> enrich -> fingerprint dedup -> v2_events
```

| Stage | Module | Contract |
|-------|--------|----------|
| Contract | `backend/telemetry/contract.py` | Immutable `EVENT`; `fingerprint()` = sha256 of (source, host, user, action, ts-ms, facts, org). |
| Normalize | `backend/telemetry/normalization/` | `WindowsEventNormalizer` (Security 4624/4625), `GenericNormalizer` (canonical JSON). Unknown shapes -> `None`, never persisted. |
| Enrich | `backend/telemetry/enrichment/` | Fail-open, read-only (threat-intel lookup, geo stub). Errors recorded in `facts.enrich_errors`, ingestion never blocked. |
| Ingest | `backend/telemetry/ingestion/` | Batch dedup by fingerprint; batch-level fallback timestamp keeps replay deterministic; one bad record never kills the batch. |
| Storage | `backend/telemetry/models.py` | `v2_events` table, unique fingerprint, JSONB facts. |

## Determinism (why it matters)

Every replay of the same records must be a no-op. Two rules guarantee it:

1. Records without a parseable timestamp use one batch-level
   `fallback_ts` (not per-record `datetime.now()`).
2. Unnormalizable records are dropped (`None`), because they have no
   deterministic identity.

## API

| Endpoint | Behavior |
|----------|----------|
| `POST /api/v2/telemetry/ingest` | Accepts `{"records": [...]}`, returns stats. Inert unless `BARAQ_TELEMETRY_V2=1`; always disabled when `BARAQ_ENV=production`. |
| `GET /api/v2/telemetry/events` | Recent `v2_events` (verification only). |

## Dev runs (synthetic, scratch DB)

```powershell
python scripts\dev_seed_telemetry.py --records 800 --seed 11
```

Creates `baraq_scratch_<uuid>`, runs the pipeline with ground-truth
synthetic telemetry (benign background + the known-problem attack patterns
from `tests/regression/v1-known-problems/`), verifies idempotent replay and
the boundary, then drops the database. Refuses to run against `sentinel`
(production), `baraq_test`, or `BARAQ_ENV=production`.

## Tests

`tests/test_telemetry_v2.py` - 11 tests: normalization shapes, fingerprint
stability, idempotent replay, malformed-record handling, enrichment
fail-open, and the no-side-effects boundary against v1 tables.
