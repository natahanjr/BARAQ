# response/ — SOAR actions (v2 boundary)

BOUNDARY — consumes `INCIDENT`s. Nothing in this tree may run without an
incident context, and destructive actions require analyst approval unless
explicitly enabled (see SAFETY below).

| Module | Contract |
|--------|----------|
| `playbooks/` | Playbook definitions + executor. Idempotent actions (no duplicate incidents/actions per alert). Fired automatically from the alert pipeline when a playbook matches - not only by the manual `/run` endpoint. |
| `actions/` | Atomic action implementations: notify, create_incident, block_ip, isolate_host, kill_process, escalate, add_note, verdict, close. |
| `unblock_ip` | The undo for `block_ip`. A firewall block has **no TTL**, so a false-positive containment is otherwise permanent - the analyst had to remove the rule by hand. Always pair a block with an unblock in the playbook. |

Each execution is recorded in `playbook_runs` (per action: status + detail,
overall status, triggered_by, org) and is visible under Automation →
Execution History, with a click-through to the alert and the playbook's
trigger conditions.

## SAFETY (Phase 0.12)

Destructive actions (`isolate_host`, `kill_process`, `delete_*`, `block_ip`
network-wide) are **disabled by default**:

- Config flag: `SOAR_DESTRUCTIVE_ACTIONS_ENABLED` (default `false`).
- When disabled, the executor records the action as `SIMULATED` and takes no
  real side effect.
- In production the server additionally **refuses to start** with
  `BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED=1`, so enabling containment is always
  a deliberate, explicit act.
- Recommended flow until v2 validation: Detection → Incident → Recommended
  action → Analyst approval → Response.

Owns: `RESPONSE` (action execution records). Emits: action results only.
