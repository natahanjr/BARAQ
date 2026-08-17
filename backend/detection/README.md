# detection/ — rule evaluation (v2 boundary)

BOUNDARY — detection consumes `EVENT`s and produces `FINDING`s. It never
creates incidents and never executes responses.

| Module | Contract |
|--------|----------|
| `rules/` | Declarative detectors (sigma + custom). Each rule: id, name, mitre mapping, severity, conditions. No side effects. |
| `engine/` | Runs rules against events; emits `FINDING`s. Pure: same input → same findings. |
| `findings/` | The `FINDING` object model: rule id, matched evidence (event ids), confidence, severity, mitre, first/last seen. |

Owns: `FINDING`. Emits: `FINDING` only.

NOT allowed: alert creation, risk mutation, incident creation, SOAR actions.
