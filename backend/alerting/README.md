# backend/alerting

Phase 3 — **DETECTION -> ALERT** management (spec 3.1-3.50). Turns eligible
detections into analyst-facing alerts with a full lifecycle, without ever
touching incidents, risk or SOAR (those are Phase 7+).

## Modules

| Module | Responsibility |
|---|---|
| `contract.py` | `ALERT` dataclass (self-validating), severities, statuses, feedback types |
| `models.py` | `v2_alerts`, `alert_occurrences`, `alert_feedback`, `alert_audit_events`, `alert_suppression_rules` |
| `fingerprint.py` | deterministic sha256 dedup key (detector/host/user/source/MITRE) |
| `eligibility.py` | detector-aware policies (ALERT-POLICY-000..005) |
| `lifecycle.py` | transition table + `IllegalTransition`; explicit reopen |
| `audit.py` | every state change recorded in `alert_audit_events` |
| `suppression.py` | auditable, expiring, scoped suppression rules (reason required, 90-day cap) |
| `feedback.py` | structured analyst feedback + FPR (>= 10 labels) |
| `deduplication.py` | per-detector windows, merge-into-active-alert rules |
| `metrics.py` | MTTA/MTTR (with sample sizes), age buckets, reduction ratios |
| `engine.py` | `process_detection(s)` — the single entry point; refuses the production DB by name |

## Pipeline

```text
detection -> eligibility (policy per detector)
           -> fingerprint -> existing ACTIVE alert in window?
                yes -> merge (occurrence, evidence, last_seen, count)
                no  -> create ALR-xxxxxx (OPEN)
```

## API

Served by `backend/api/alerting.py` under `/api/alerts-v2/*` (v1 owns
`/api/alerts`). Gated by `ALERTS_V2_ENABLED` (env `BARAQ_ALERTS_V2`,
PEP 562 fallback). All state changes are validated (409/422) and audited.

## Rules of the road

- Only ever write the five tables above; never `incidents`/`entity_risk`/
  risk/playbooks.
- Never derive alert state from anything non-deterministic (no ML).
- Every suppression needs a reason, a scope and a bounded expiration.
- Reopening a RESOLVED/CLOSED/SUPPRESSED alert is an explicit operation.
- Evidence is preserved per occurrence; alerts never say "Rule matched".

See `docs/phase3/` for the full contract, lifecycle, dedup and feedback docs.