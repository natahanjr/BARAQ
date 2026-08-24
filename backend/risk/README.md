# risk/ — entity risk accumulation (v2 boundary)

BOUNDARY — consumes `DETECTION`s and evidence; mutates per-entity risk
scores. Readable by incident creation. Never creates alerts or incidents.

| Module | Contract |
|--------|----------|
| `entity/` | Per-entity risk state (host/user): score, level, history, decay. Single source of truth for risk_level. |
| `scoring/` | The one documented scoring function used everywhere (risk → severity mapping). No parallel implementations. |

Owns: `RISK`. Emits: risk state / risk events only.

NOT allowed: alert or incident creation.
