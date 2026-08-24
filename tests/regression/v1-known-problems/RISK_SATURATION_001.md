# RISK_SATURATION_001 — incident risk levels do not reflect severity

Captured from the v1 live database on 2026-08-17 (baseline-v1-2026-08-17).

## Input
Alerts and incidents produced by the v1 detection pipeline on 2026-08-17.

## v1 behavior
Incident severity and risk level are inconsistent:

```text
#61 'Playbook incident: Data Encrypted for Impact (Ransomware)'  critical / MEDIUM
#64 'Playbook incident: System Recovery Inhibited'               critical / MEDIUM
#63 'Incident: Correlated: defense_evasion_campaign'             high     / LOW
#59 'Incident: Brute Force Attack'                               critical / CRITICAL
#60 'Incident: BARAQ - Failed Logon Brute Force (aggregation)'   high     / MEDIUM
```

Critical incidents are routinely tagged `MEDIUM` risk, and a correlated
defense-evasion campaign is `LOW`. Severity and risk scores come from
different code paths (alerting vs. correlation vs. playbook) and are never
reconciled.

Additionally, `critical + high` open incidents: 10, of which 8 unassigned.

## V2 expected behavior
- risk_level derived from a single, documented scoring function shared by
  alerts and incidents.
- Incident severity == function(risk_level, evidence), consistent by
  construction.
- A critical-severity incident can never be tagged `LOW` risk.

## Regression
- Replay: create an incident from a critical alert with 5 linked events.
- Assert: risk_level >= HIGH and severity == 'critical'.
