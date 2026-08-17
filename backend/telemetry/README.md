# telemetry/ — raw data intake (v2 boundary)

BOUNDARY — nothing in this tree may call detection, correlation, risk or
incident code. It is input-only.

| Module | Contract |
|--------|----------|
| `ingestion/` | Collectors push raw events here. One normalized schema (`EVENT`), idempotent ingestion (dedup by event fingerprint), no alerting. |
| `normalization/` | Raw record → canonical `EVENT` (timestamp, host, user, source, action, facts). No thresholds. |
| `enrichment/` | Adds context (geo, threat intel, asset metadata) to an EVENT. Never blocks ingestion. |

Owns: `EVENT`. Emits: `EVENT` only.

NOT allowed: reading alerts/incidents tables, writing alerts, running rules.
