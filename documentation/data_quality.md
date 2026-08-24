# Data quality & auto-fix of corrupted event data

Windows event-rendering (SafeFormatMessage) can truncate structured values
into *corrupted* debris — a process image reduced to a bare letter (`C`,
`F`, `\`, `g`). BARAQ previously forwarded those records to the detection
engine, so rules fired on garbage and the alert queue filled with false
positives. This feature validates every record, discards corrupted debris
*before* detection, tracks the corruption rate and can auto-repair the
source.

## Pipeline behaviour

1. `backend/collectors/validation.py` — pure validation rules:
   - `validate_raw_record()` — structural checks (dict, source, integer
     event_id).
   - `structured_record_is_corrupted()` — process/network records whose
     name/path/command-line are debris.
   - `normalized_is_corrupted()` — normalized events whose facts carry a
     debris process image / command line, or an explicitly empty user.
   - `orm_event_is_corrupted()` — same check against stored
     `NormalizedEvent` rows (defence-in-depth for ML).
   - Missing values are **not** corruption: partial paths / truncated
     messages are already handled by the normalizer's `data_integrity`
     flag and the rules engine's demotion path, so no real events are lost.

2. `run_pipeline()` (`backend/api/system.py`) validates every record —
   local collector and remote agents alike — and **discards corrupted
   records before persistence and detection**. Each discard increments the
   `corrupted_events` counter and feeds the quality tracker.

3. ML (`backend/ml/anomaly.py`) skips corrupted rows in the training
   loaders and the scoring loop, so even history that predates the
   validation layer is never trained on.

## Quality tracking

`backend/collectors/quality.py` keeps a thread-safe sliding window (default
10 minutes) of per-channel outcomes and exposes:

| Endpoint | Purpose |
| --- | --- |
| `GET /api/system/data-quality` | Live window + last 12 snapshots |
| `GET /api/system/data-quality/history?limit=50` | Persisted snapshots (oldest first) |
| `POST /api/system/data-quality/repair` | Manual repair sequence (admin) |
| `GET /api/health` | Now includes `data_quality` status + rate |

Status mapping (thresholds configurable):

| Status | Corruption rate | Action |
| --- | --- | --- |
| `healthy` | < 10% | none |
| `warning` | 10–30% | monitor |
| `degraded` | 30–50% | consider repair |
| `critical` | ≥ 50% | auto-repair |

## Repair sequence

`backend/collectors/repair.py` runs best-effort steps — each failure is
recorded and never aborts the rest:

1. clear `Security` + `System` event logs (`wevtutil cl`),
2. restart the Windows EventLog service (`sc`),
3. wait ~5 s for stabilisation,
4. kick a background ML retrain on the cleaned history,
5. audit entry (`data_quality.repair`) + notification via the standard
   alerting channels.

The background monitor (`backend/monitor/data_quality.py`) persists a
snapshot every `BARAQ_DATA_QUALITY_MONITOR_SECONDS` and triggers the
sequence automatically when the window rate crosses the CRITICAL threshold
(repair cooldown `BARAQ_DATA_QUALITY_REPAIR_COOLDOWN_MINUTES` prevents
thrash). Outside Windows the OS steps report `skipped`; privilege errors
report `failed` without blocking the sequence.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `BARAQ_DATA_QUALITY_WINDOW_MINUTES` | `10` | sliding window length |
| `BARAQ_DATA_QUALITY_WARN_RATE` | `0.10` | warning threshold |
| `BARAQ_DATA_QUALITY_DEGRADED_RATE` | `0.30` | degraded threshold |
| `BARAQ_DATA_QUALITY_CRITICAL_RATE` | `0.50` | critical / auto-repair threshold |
| `BARAQ_DATA_QUALITY_AUTO_REPAIR` | `1` | auto-trigger the repair sequence |
| `BARAQ_DATA_QUALITY_MONITOR_SECONDS` | `60` | monitor cadence |
| `BARAQ_DATA_QUALITY_REPAIR_COOLDOWN_MINUTES` | `15` | minimum gap between repairs |

The dashboard shows the live status, corruption rate, top reasons and a
manual repair button under Settings → System (Data Quality card).
