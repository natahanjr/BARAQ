# DUPLICATE_RULES_001 — overlapping alert families for one campaign

Captured from the v1 live database on 2026-08-17 (baseline-v1-2026-08-17).

## Input
One brute-force campaign against `ml-host` (60 failed logons from a public
IP, 10:32:27-10:32:30).

## v1 behavior
Three separate alert families fired for the same campaign:

```text
#142  'Brute Force Attack'                        (hybrid, event_count=60)
#143  'BARAQ - Failed Logon Brute Force (aggregation)'  (rule, aggregation)
#144..158 'Failed Logon From Public IP'           (hybrid, 15 x event_count=1)
```

No single view ties them together; dedup key spaces (rule id, correlation
id, aggregation) never meet.

## V2 expected behavior
- One detection object per campaign, one alert, one incident (unless
  escalation).
- Aggregation and per-event rules must be mutually exclusive by
  construction (aggregate rules own the campaign; leaf rules feed the
  aggregate and do not emit their own alerts).

## Regression
- Replay: the brute-force campaign above.
- Assert: exactly 1 alert; alerts-per-campaign == 1.
