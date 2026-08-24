# BARAQ SOC Contract (Phase 0.10)

The object model contract for BARAQ v2. Every layer owns exactly one
concept and may only consume the concept above it. This document is
normative — code that violates it is a bug.

## The pipeline

```text
EVENT
  ↓
FINDING
  ↓
DETECTION
  ↓
ALERT
  ↓
CORRELATION
  ↓
INCIDENT
```

NOT: `EVENT → INCIDENT`.

## The contract

| Concept | Definition | Owned by | Never does |
|---------|-----------|----------|------------|
| `EVENT` | Something happened. One normalized record: timestamp, host, user, source, action, facts. | `telemetry/` | alerting, risk mutation, thresholds |
| `FINDING` | A detector thinks something is interesting. Rule id + matched evidence (event ids) + confidence + severity + mitre. | `detection/` | alert creation, incidents |
| `DETECTION` | A finding (or aggregated/chain of findings) with sufficient evidence to represent suspicious behavior. | `correlation/` | incidents, responses |
| `ALERT` | A detection presented to an analyst. **1:1 with DETECTION.** | `correlation/` | >1 alert per detection |
| `INCIDENT` | A correlated security situation requiring investigation. Idempotent per correlation key. | `incidents/` | response execution |
| `RISK` | Accumulated contextual danger associated with an entity/case. Single documented scoring function. | `risk/` | alert/incident creation |
| `RESPONSE` | An action taken because of an incident. Destructive actions require approval by default. | `response/` | running without incident context |

## Invariants (enforced as regression tests)

1. One campaign → one DETECTION → one ALERT → at most one open INCIDENT.
2. No per-event alerts (v1 bug: `RDP_DUPLICATION_001`, `BRUTE_FORCE_OVERALERTING_001`).
3. Incident creation is idempotent (v1 bug: `INCIDENT_DUPLICATION_001`).
4. Severity and risk_level derive from the one scoring function
   (v1 bug: `RISK_SATURATION_001`).
5. No metric is reported without (definition, dataset, window, threshold,
   calculation) — see `METRICS_REGISTRY.md` (v1 bug: `ML_ANOMALY_OVERFLAGGING_001`).

## v1 → v2 reuse decision

| Reusable | Replaceable |
|----------|-------------|
| database infrastructure, auth, API framework, frontend components, telemetry collectors, logging, deployment | detection engine, alert engine, correlation engine, risk engine, incident engine, ML decision logic |

See `tests/regression/v1-known-problems/` for the baseline failure states.
