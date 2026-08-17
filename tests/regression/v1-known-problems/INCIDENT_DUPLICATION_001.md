# INCIDENT_DUPLICATION_001 — one alert opens two incidents

Captured from the v1 live database on 2026-08-17 (baseline-v1-2026-08-17).

## Input
Single alert #152 "Data Encrypted for Impact (Ransomware)" and single alert
#154 "System Recovery Inhibited", processed by the enabled automation
playbook "Open incident on impact" (playbook id 9, trigger `auto`).

## v1 behavior
The playbook ran twice against the SAME alert, opening two incidents each:

```text
playbook_runs 263 + 264 -> alert 152 -> incidents #61 AND #62  (identical)
playbook_runs 265 + 266 -> alert 154 -> incidents #64 AND #65  (identical)
```

Root cause: no idempotency check — the playbook action does not verify an
incident already exists for the alert / correlation key before creating a
new one.

## V2 expected behavior
- `create_incident` is idempotent on (alert id / correlation key): replaying
  the playbook on an alert with an existing open incident must re-open
  nothing; at most it adds a note or returns the existing incident.
- Playbook execution itself must be serialized per alert (one run at a time).

## Regression
- Replay: run "Open incident on impact" twice against the same alert.
- Assert: exactly 1 incident exists per alert.
