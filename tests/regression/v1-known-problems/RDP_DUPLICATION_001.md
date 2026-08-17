# RDP_DUPLICATION_001 — RDP remote logon spams 1 alert per event

Captured from the v1 live database on 2026-08-17 (baseline-v1-2026-08-17).

## Input
A series of RDP remote interactive logon events against `ml-host` arriving
within seconds of each other (10:42:10.4, 10:42:10.6, 10:42:10.7, 10:42:10.9 ...).

## v1 behavior
The `rdp_lateral` rule fired once per event. At baseline capture there were
**30 open alerts** with identical name/host within a ~40s window:

```text
alerts 169..198 (open)  rule=rdp_lateral  host=ml-host
name:  'RDP Remote Interactive Logon'
event_count per alert: 1
```

Plus an additional `RDP Remote Interactive Logon` incident (#69) opened on
top of the same noise.

## V2 expected behavior
5+ identical RDP logons within 5 minutes:

- 1 aggregated detection (dedup key = rule + host + user + source)
- 1 alert
- No incident unless additional evidence (escalation, brute-force pattern,
  lateral-movement chain) exists.

## Regression
- Replay: replay the `rdp_lateral` event series into v2.
- Assert: alert count == 1 (not 30); no incident.
