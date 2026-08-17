# response/ — SOAR actions (v2 boundary)

BOUNDARY — consumes `INCIDENT`s. Nothing in this tree may run without an
incident context, and destructive actions require analyst approval unless
explicitly enabled (see SAFETY below).

| Module | Contract |
|--------|----------|
| `playbooks/` | Playbook definitions + executor. Idempotent actions (no duplicate incidents/actions per alert). |
| `actions/` | Atomic action implementations: notify, create_incident, block_ip, isolate_host, kill_process, escalate, add_note, verdict, close. |

## SAFETY (Phase 0.12)

Destructive actions (`isolate_host`, `kill_process`, `delete_*`, `block_ip`
network-wide) are **disabled by default**:

- Config flag: `SOAR_DESTRUCTIVE_ACTIONS_ENABLED` (default `false`).
- When disabled, the executor records the action as `SIMULATED` and takes no
  real side effect.
- Recommended flow until v2 validation: Detection → Incident → Recommended
  action → Analyst approval → Response.

Owns: `RESPONSE` (action execution records). Emits: action results only.
