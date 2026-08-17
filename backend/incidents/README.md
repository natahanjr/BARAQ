# incidents/ — case lifecycle (v2 boundary)

BOUNDARY — consumes `DETECTION`s and `RISK`; produces `INCIDENT`s. Creation
is idempotent (one open incident per correlation key).

| Module | Contract |
|--------|----------|
| `creation/` | DETECTION → INCIDENT rules: what evidence level justifies an incident; keyed on correlation_id; never duplicates. |
| `lifecycle/` | Status transitions (open → in_progress → resolved), timestamps, comments. |
| `assignment/` | Owner assignment, queues, SLA. |

Owns: `INCIDENT`. Emits: `INCIDENT` only.

NOT allowed: response/action execution.
