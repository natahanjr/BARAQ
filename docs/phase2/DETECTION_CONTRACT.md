# Phase 2: Detection Contract (v2)

`EVENT -> DETECTION` only. Phase 2 creates detections; nothing here may
create alerts, incidents, risk updates, SOAR actions or ML dependencies
(hard boundary, enforced by tests).

## Canonical DETECTION (contract v2.0)

| Field | Meaning |
|-------|---------|
| `detection_id` | Deterministic campaign id: `DET-<detector>-<sha12>` — see "Identity" below |
| `detector_id` / `detector_version` | Which rule fired; versioned from day one |
| `event_id` | Fingerprint of the triggering event |
| `event_ids` | All events the detection aggregates (merged on replay) |
| `timestamp` / `first_seen` / `last_seen` | Detection time / campaign span |
| `event_type` | Canonical classification (`authentication`, `process`, `file`, ...) |
| `host_id`/`host_name`, `user_id`/`username`, `source_ip`, `destination_ip` | Context |
| `title` / `description` | Human-readable |
| `severity` | `low` \| `medium` \| `high` \| `critical` (how dangerous IF malicious) |
| `confidence` | 0.0–1.0, 3 decimals; separate from risk (Phase 6) |
| `mitre_tactic` / `mitre_technique` | ATT&CK mapping |
| `evidence` | Per-field `{field, value, reason}` — never a bare "rule matched" |
| `observables` | STIX-style `{type, value}` triples for pivoting |
| `status` | `new` \| `expired` \| `suppressed` (Phase 2 keeps it minimal) |

## Identity (dedup / aggregation)

`detection_id = make_detection_id(detector_id, *parts)` (sha256, 12 hex).

Detectors choose the campaign key — the parts that make repeated events
the same campaign:

| Detector | Key parts | Effect |
|----------|-----------|--------|
| D001 External RDP | `host, user, source_ip` | an RDP burst from one source to one account = one detection |
| D002 Brute Force | `host, user` | one detection per account under attack |
| D003/D004/D005 | (default: event fingerprint + title) | per-event identity |

`persist()` is idempotent per `detection_id`: a re-fire updates the
existing row — merges `event_ids`, widens `first_seen`/`last_seen`,
refreshes severity/confidence/evidence/description — never duplicates.
One row per rule + campaign key. This is what fixes
`RDP_DUPLICATION_001` (30 v1 alerts -> 1 v2 detection) and
`BRUTE_FORCE_OVERALERTING_001` (15 per-event alerts -> 1 aggregate).

## Engine boundaries (non-negotiable)

* `run_detection` / `run_detections` are pure: same event -> same
  detections, zero writes (verified against `alerts`, `incidents`,
  `entity_risk`, `detections`).
* `persist` writes the `detections` table **only**, and refuses the
  production DB (`sentinel`) by name.
* Detector failures are logged and swallowed — one bad detector never
  kills a run.
* Severity values are validated; confidence is clamped and rounded.

## API

| Endpoint | Behavior |
|----------|----------|
| `GET /api/detections` | List with filters `detector_id`, `severity`, `status`, `limit`, `offset` |
| `GET /api/detections/detectors` | Registry overview (id, name, version, MITRE, enabled) |
| `GET /api/detections/detectors/{id}` | Detector detail |
| `POST /api/detections/evaluate` | `{"records": [...]}` -> normalize -> run -> persist; returns created/updated detections |
| `GET /api/detections/{detection_id}` | Single detection |

Gated by the same `TELEMETRY_V2_ENABLED` flag as Phase 1: `BARAQ_TELEMETRY_V2=1`
in non-production; always disabled when the configured DB is `sentinel`.

## Statuses

`new` = created and unreviewed. `expired`/`suppressed` are lifecycle
states reserved for later phases; the API accepts them, the engine only
ever emits `new`.
