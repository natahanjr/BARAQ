# BARAQ Search Language Reference

BARAQ ships a pipe-based query language over its
normalized event store and its alert store. The same syntax drives the
**Search** page, **saved searches**, **dashboard panels** and the REST API
(`POST /api/search`).

---

## Anatomy of a query

```
<filters + free text> [ | <pipe> [args] | <pipe> [args] ... ]
```

```
source=sysmon event_id=4625 "failed logon" user=admin | stats count by host | sort -count | limit 100
```

- Everything before the first `|` selects records (filters + free text).
- Pipes transform the result set, chained left to right.
- A query may be a bare filter search with no pipes at all.

## Indexes and time windows

- `index=alerts` — search the **alert** store (columns: `id, name, severity,
  status, confidence, score, rule, host, org, mitre_id, mitre_name,
  mitre_tactic, risk_score, risk_level, event_count, detection_method,
  created_at, evidence`). Default: `index=events`.
- `index=events` — search **normalized telemetry** (columns: `id, event_id,
  category, source, user, host, org, risk, risk_score, severity, message,
  timestamp, data_integrity, is_anomaly, ml_score`).

Time windows are relative offsets or ISO timestamps:

| Value | Meaning |
|---|---|
| `-15m` `-1h` `-24h` `-7d` `-30d` | relative offset from now |
| `2026-08-01T00:00:00Z` | exact ISO instant |

The API accepts `earliest` / `latest` (`POST /api/search` body) or the
default window of the last 24 h. `earliest` must be before `latest`.

## Filters

```
field=value          exact match (typed coercion: int, float, bool, datetime)
"free text phrase"   verbatim match against the message / evidence text
```

Filters AND together. Values with spaces must be quoted. Unknown fields are
rejected with an error listing the valid columns.

## Pipes

### `stats` — group and aggregate

```
| stats count by user
| stats count, avg(risk_score) by user, host
| stats sum(bytes_sent) by source
```

Aggregations: `count`, `sum(field)`, `avg(field)`, `max(field)`, `min(field)`.
At least one group-by field is required after `by`.

### `top` / `rare` — value frequency

```
| top 10 user             # most frequent users (default N=10)
| top 5 user by host
| rare 3 event_id         # least frequent
```

### `table` — pick columns

```
| table user, host, count
```

Drops every other column. `sort` / `where` after `table` operate on the
projected columns.

### `fields` — keep / drop

```
| fields -message, -org    # drop
| fields user, host        # keep
```

### `sort` — order rows

```
| sort -count              # descending
| sort +host, -count       # ascending host, then descending count
```

Works on aggregated and raw (post-`table`) results. Sort fields must be
present in the result columns.

### `where` — filter aggregated / projected rows

```
| where count>5
| where risk_score>=60
| where user=alice
```

Operators: `=` `==` `>` `>=` `<` `<=`. Numeric values compare numerically.

### `limit` — cap rows

```
| limit 100
```

### `timechart` — time-bucketed trends

```
| timechart span=1d count
| timechart span=1h count by user
| timechart span=1h avg(risk_score)
| timechart span=15m count
```

- `span` accepts `Ns` `Nm` `Nh` `Nd` `Nw` (default `1h`).
- Without `by`: columns `_time, count` (or the requested aggregations).
- With a single `by` field and `count`: results **pivot** —
  columns `_time, count, <value-1>, <value-2>, …`; the leading `count` is the
  bucket total, per-value columns hold that value's count (0 when absent).
- Buckets are UTC-aligned to the epoch; empty buckets are omitted.
- `sort` / `where` chain after `timechart` (`| timechart span=1d count by
  user | sort -count`).

### `transaction` — group events into sessions

```
| transaction by host
| transaction by user maxspan=30m
| event_id=4625 | transaction by host maxspan=5m
```

- Groups records with the same key field into transactions whenever the gap
  between consecutive events is at most `maxspan` (default `5m`).
- Output columns: `_time` (session start), `duration` (seconds), `count`,
  and the key field. Newest session first.
- Useful for sessionizing brute-force bursts, beacon activity, or
  multi-stage operations on one entity.

## Errors

Malformed queries return HTTP 400 with a human-readable message, e.g.:

- `unknown field 'bogus' in index 'events'`
- `stats requires aggregations with 'by', e.g. | stats count by user`
- `unterminated quote`

## API

```http
POST /api/search
Content-Type: application/json
X-API-Key: <key>

{ "query": "event_id=4625 | top 10 user", "earliest": "-7d", "limit": 100 }
```

Response:

```json
{
  "index": "events",
  "query": "event_id=4625 | top 10 user",
  "columns": ["user", "count"],
  "rows": [["alice", 42]],
  "total": 1,
  "elapsed_ms": 3.1
}
```

Autocomplete hints: `GET /api/search/suggest?q=sta`.

## Example hunts

```text
# Failed logons per account, worst first
event_id=4625 | stats count by user | sort -count

# Daily failed-logon volume, pivoted by category
event_id=4625 | timechart span=1d count by category

# One brute-force session on a single host
event_id=4625 | transaction by host maxspan=5m | sort -count

# Open critical alerts, highest risk first
index=alerts severity=critical status=open | table name, rule, host, risk_level, risk_score | sort -risk_score

# Powershell hosts downloading content
index=events source=powershell "DownloadString" | top 5 user

# Events linked to a user with risk above medium
user=alice risk>=Medium | table event_id, category, risk | sort -risk
```

Saved searches wrap a query plus its window (`earliest`) for one-click
re-runs; dashboards pin saved searches as `table` / `count` / `top` / `area`
panels, so a panel can simply be a `timechart` rendered as an area chart.
