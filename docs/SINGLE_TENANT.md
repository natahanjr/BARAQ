# Single-tenant deployment

**BARAQ is deployed as a single-tenant SOC platform: one organization, one set
of analysts, no external customers.** This document records what that decision
means for the codebase, and the one place where it does not yet hold.

## What "single-tenant" buys you

Most read paths carry an `org` column and are filtered per analyst. A session
user sees only their own organization's records; admins see everything. This is
covered by `tests/test_tenant.py` and is enforced in code, not by convention.

The `org` value is attached at ingest: the reporting agent's configured
organization is stamped onto every normalized event, and from there onto alerts,
endpoints and incidents. `X-Org` lets an admin narrow their view for the frontend
org switcher; it is ignored for non-admins, so an analyst can never widen scope
by setting a header.

## The gap: surfaces with no `org` column

Fifteen API surfaces have **no tenant column on their backing tables**, so there
is nothing for `tenant_scope()` to filter on. Today any authenticated analyst
can read them:

| Surface | Backing table has `org`? |
|---|---|
| `/api/alerts-v2` (`v2_alerts`) | no |
| `/api/incidents-v2` (`incidents_v2`) | no |
| `/api/risk`, `/api/ueba`, `/api/investigation` | no |
| `/api/intel`, `/api/behavior-groups`, `/api/integrations` | no |
| `/api/datasets`, `/api/compliance`, `/api/detections` | no |
| `/api/v2/telemetry`, `/api/bookmarks`, `/api/evaluation` | no |
| `/api/insider-threat` | no |

`entity_nodes` is the same problem for the entity graph, which has API-layer
isolation only.

**In a single-tenant deployment this is not a data leak** — there is no second
tenant to leak into. It matters for three other reasons:

1. If this is ever offered to a second organization, the isolation is not there.
2. Role-based access control is weaker than it looks. An `analyst` account
   currently reaches operational and evaluation surfaces as well as the
   day-to-day ones.
3. The isolation that *is* enforced depends on every query remembering to filter.
   That is a convention, and conventions fail.

## Why these are not simply admin-only

Restricting these routers to `require_admin` was implemented and reverted. It
returns 403 to every analyst and blanks eight analyst-facing screens, because
the frontend calls them with no role check:

| Surface | Called by |
|---|---|
| `/api/bookmarks` | `Bookmarks.jsx` |
| `/api/compliance/export` | `ComplianceGap.jsx` |
| `/api/intel/feeds` | `Dashboard.jsx` |
| `/api/insider-threat/scores` | `InsiderThreat.jsx` |
| `/api/ueba/baselines` | `UEBA.jsx` |
| `/api/detections` | `api.js` (`detectionDetail`) |
| `/api/evaluation/*` | `api.js` (5 call sites) |
| `/api/investigation/process-tree` | `api.js` (`investigate`) |

Security work that breaks the product is not a fix. The gap is left visible and
documented instead.

## Resolving it

Pick one, in order of preference:

1. **Add an `org` column to the tenant-less tables**, backfill, and filter
   properly. The only option that makes the platform genuinely multi-tenant.
   Work: a migration per table, propagating `org` from the source events, and
   extending `tenant_scope()` usage across the fifteen routers.
2. **Gate to admin and add the matching role check in each component.** Viable
   if the affected screens are genuinely admin-only. Requires deciding, per
   screen, whether an analyst should see it.
3. **Keep them analyst-accessible and state the assumption.** Acceptable *only*
   while the deployment is genuinely single-tenant, and only if it is written
   into the operational docs and reviewed at each release. This document is that
   record.

Option 3 is where the project stands today.

## Tests

`tests/test_single_tenant.py` is an executable specification of the gap. It
currently reports **14 failures, 18 passes**:

- The 14 failures are `test_analyst_is_refused_on_tenant_less_surfaces` — the
  documented gap. They are expected to fail until one of the options above is
  implemented, and are kept in the suite deliberately: a silent pass would mean
  the gap closed without anyone noticing.
- The 18 passes assert what already holds: admins are never locked out, the
  tenant-scoped surfaces stay analyst-accessible, and an unauthenticated caller
  is refused everywhere.

To exclude it until the decision is made:

```
pytest tests -k "not single_tenant"
```

Add `--timeout=90` when running it in isolation; without a timeout the suite can
exceed 15 minutes on a cold database.
