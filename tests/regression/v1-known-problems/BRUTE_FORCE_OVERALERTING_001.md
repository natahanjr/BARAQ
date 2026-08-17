# BRUTE_FORCE_OVERALERTING_001 — one alert per failed logon

Captured from the v1 live database on 2026-08-17 (baseline-v1-2026-08-17).

## Input
A stream of failed logon events from public IPs (logon-type 3), one event at
a time, arriving ~200ms apart.

## v1 behavior
The hybrid rule `f88e112a-21aa-44bd-9b01-6ee2a2bbbed1` ("Failed Logon From
Public IP") created **15 open alerts** (ids 144..158) in ~2 seconds, every
alert with `event_count=1`:

```text
144  10:32:28.62  medium  event_count=1
145  10:32:28.93  medium  event_count=1
146  10:32:29.11  medium  event_count=1
...
```

Meanwhile `brute_force` (hybrid) produced alert #142 `event_count=60` and
`baraq-4625-brute-force` produced alert #143 in the same second — three
alert families for the same campaign.

## V2 expected behavior
- Single failed logon from a new public IP: 1 low-severity alert (or none).
- N failed logons within a window from the same source: 1 aggregated alert,
  severity/escalation scaled by N and user count.
- The same campaign must not produce 3 parallel alert families.

## Regression
- Replay: replay 60 failed logons from one public IP over 60s into v2.
- Assert: <= 2 alerts total; exactly 1 of them represents the aggregate;
  no per-event alerts.
