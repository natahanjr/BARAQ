# Correlation Contract

## What a finding is (spec 5.1-5.4)

A **correlation finding** connects behavior groups into an explainable
attack *hypothesis*. It is:

- NOT an incident;
- NOT a risk score;
- NOT a confirmation of compromise.

Every value is deterministic and bounded; titles never overclaim (the
`BANNED_CORRELATION_PHRASES` hard-fail list is enforced both at
construction and by tests).

## Finding fields (spec 5.3)

| Field | Meaning |
|-------|---------|
| `correlation_id` | public id `CF-<6-digit sequence>` - never the fingerprint |
| `fingerprint` | sha256 of (type + sorted member ids + normalized edges) |
| `correlation_type` | most specific claim the evidence supports (below) |
| `status` | NEW / ACTIVE / QUIET / CLOSED |
| `member_group_ids` | behavior groups in sequence order |
| `member_alert_ids` | every alert of every member (DoD = 30) |
| `entities` / `hosts` / `users` / `source_ips` | deterministic aggregates |
| `mitre_tactics` / `mitre_techniques` | deterministic aggregates |
| `observables` | merged destination hosts etc. |
| `confidence` | bounded 0..1, deterministic (spec 5.23) |
| `highest_severity` | strongest member severity - never escalated (spec 5.25) |
| `title` / `description` | pattern language, "why" reasons from rules |

## Correlation types (spec 5.4)

TEMPORAL, ENTITY, HOST_CHAIN, USER_CHAIN, SOURCE_CHAIN, TACTIC_SEQUENCE,
TECHNIQUE_SEQUENCE, LATERAL_MOVEMENT, MULTI_STAGE.

Type resolution priority (most specific claim first):

1. `LATERAL_MOVEMENT` - a lateral-movement edge exists in the chain;
2. `HOST_CHAIN` - 3+ distinct hosts *and* a network/destination relation edge;
3. `MULTI_STAGE` - 3+ members spanning 2+ tactic phases;
4. the creating pair rule's type.

## Edge relationship types (spec 5.20)

TEMPORAL, SAME_HOST, SAME_USER, SAME_SOURCE, SAME_ACCOUNT,
NETWORK_RELATION, DESTINATION_RELATION, TECHNIQUE_TRANSITION,
TACTIC_TRANSITION, LATERAL_MOVEMENT.

- `DESTINATION_RELATION`: the earlier group's destination hosts intersect the
  later group's hosts.
- `NETWORK_RELATION`: both groups targeted the same destination.
- `SAME_ACCOUNT` is only ever emitted by rule R002.
- Technique transitions only exist inside one behavior family (MITRE is
  context, never proof - spec 5.17).

## Edge strength (spec 5.21)

Sum of the weight categories actually shared (each category counted once),
capped at 1.000:

| Category | Weight | Relationship types |
|----------|--------|--------------------|
| host     | .30    | SAME_HOST |
| user     | .25    | SAME_USER, SAME_ACCOUNT |
| source   | .20    | SAME_SOURCE |
| time     | .15    | TEMPORAL |
| technique| .10    | TECHNIQUE_TRANSITION, TACTIC_TRANSITION |

Qualitative signals (NETWORK_RELATION, DESTINATION_RELATION,
LATERAL_MOVEMENT) count for confidence factors but never inflate strength.

## Confidence (spec 5.23-5.24)

Deterministic formula over the finding's shared evidence - never summed
from group confidence values:

```
base 0.40
+ 0.10 * (distinct edge relationship types - 2)   [min 0]
+ 0.10  if any consecutive member pair progresses tactic phases
+ 0.05  if 3+ members
+ 0.03  if a LATERAL_MOVEMENT edge exists
clamped to [0.20, 0.90]
```

The spec 5.70 canonical chain (5 relationship types, progression, 5
members, lateral edge) is exactly **0.88**.

## Phase map (spec 5.18)

T1133/T1190/T1566.001 -> INITIAL_ACCESS; T1110*/T1621 ->
CREDENTIAL_ACCESS; T1021*/T1570 -> LATERAL_MOVEMENT; T1059*/T1047/
T1053.005 -> EXECUTION; T1486 -> IMPACT (context only). Unknown techniques
map to UNKNOWN_PHASE and never drive a progression claim.

## Banned claims (spec 5.26-5.28)

`confirmed attack`, `confirmed compromise`, `attacker confirmed`,
`breach confirmed`, `apt confirmed`, `malware confirmed`,
`host compromised`, `account compromised`, `confirmed intrusion`, `proves`.
Any of these in an auto-generated title/description raises a hard error.