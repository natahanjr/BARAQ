# Threat-Intel Feeds (roadmap 4.3)

BARAQ ingests external threat-intel feeds into its DB-cached indicator store
(`threat_intel_records`), so the existing enrichment pipeline
(`backend/threatintel`) and the new IOC matcher all see the same
known-bad set.

## Supported feed types

| Type | Source | Notes |
|---|---|---|
| `taxii` | TAXII 2.1 server | `GET /collections` discovery, then collection objects; STIX 2.1 `indicator` patterns parsed for IP / domain / SHA-256 / SHA-1 / MD5 / URL |
| `stix` | Plain STIX 2.1 JSON bundle | Same object/pattern parser as TAXII |
| `misp` | MISP `attributes/restSearch` | `to_ids=1` only; attribute types mapped to ip / domain / hash |
| `csv` / `url` | Plain text / CSV | One indicator per line; `#`, `;`, `//` comments ignored |

## Configuration

```json
# backend/config.py: BARAQ_THREAT_INTEL_FEEDS (JSON list)
[
  {"name": "misp-prod",  "type": "misp",  "url": "https://misp.corp.local",
   "api_key": "..."},
  {"name": "taxii-cti",  "type": "taxii", "url": "https://taxii.corp.local",
   "api_key": "...", "collection_id": "<collection-guid>"},
  {"name": "stix-bundle","type": "stix",  "url": "https://dl.example/bundle.json"},
  {"name": "plainlist",  "type": "csv",   "url": "https://dl.example/iocs.txt"}
]
```

| Setting | Default | Purpose |
|---|---|---|
| `BARAQ_THREAT_INTEL_FEEDS` | `[]` | JSON feed subscription list |
| `BARAQ_THREAT_INTEL_FEED_MAX_IOCS` | `5000` | Per-feed cap per refresh |
| `BARAQ_THREAT_INTEL_FEED_MIN_CONFIDENCE` | `0.6` | IOC matching confidence floor |
| `BARAQ_THREAT_INTEL_TIMEOUT` | `8` | Feed HTTP timeout (seconds) |

## Refresh

* Scheduler: every 720 cycles (~3 h at the default 15 s interval) via
  `backend.intel.feeds.refresh_feeds` (`backend/main.py`).
* Celery: `baraq.intel_refresh` task (see `backend/celery_app.py`).
* Manual: `POST /api/intel/feeds/refresh` (admin) or
  `GET /api/intel/feeds` to inspect last-run state.

Per-feed state (`threat_intel_feed_state`): `last_success_at`, `last_error`,
`ioc_count`, `total_fetched`. A failing feed is reported and never blocks
the scheduler loop. Upserts never downgrade an existing record's confidence
and merge source labels.

## API

| Endpoint | Access | Purpose |
|---|---|---|
| `GET /api/intel/feeds` | any authenticated | Subscriptions + last-run state |
| `POST /api/intel/feeds/refresh` | admin | Run ingestion once (audited) |
| `POST /api/intel/match` | any authenticated | Match text against known-bad indicators |
| `POST /api/intel/lookup` | any authenticated | Full reputation lookup for one indicator |

## IOC matching

`match_text(db, text)` extracts IP / domain / hash candidates and returns
cache rows whose category is `malicious`/`suspicious` at or above
`BARAQ_THREAT_INTEL_FEED_MIN_CONFIDENCE`. Analysts can flag new IOCs via
`POST /api/intel/save` (confidence 1.0, source `analyst`), and they join
the same matching pool immediately.