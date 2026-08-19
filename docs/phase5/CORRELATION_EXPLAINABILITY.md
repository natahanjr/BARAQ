# Correlation Explainability

Every finding answers three questions: **why does it exist**, **why is
this group a member**, and **what did the sequence look like**.

## Why the finding exists

`description` is assembled from the matching rules' `description` fields
(which carry the concrete "why": e.g. "rule R005: source 198.51.100.9
touched multiple hosts (2)"). Titles are pattern language from
`TYPE_TITLES` - "Potential Lateral Movement Sequence", never
"Lateral movement confirmed".

## Edges (spec 5.19-5.21)

Each pair of consecutive member groups has one `correlation_edges` row per
relationship type:

- `source_group_id` / `target_group_id` - the ordered pair;
- `relationship_type` - SAME_USER, DESTINATION_RELATION, ...;
- `time_delta_seconds` - the gap between the two groups' first_seen;
- `shared_entities` / `shared_techniques` - the concrete overlap;
- `evidence` - field/value/reason rows;
- `strength` - deterministic weight sum (see contract doc).

## Membership reasons (spec 5.19)

Every `correlation_members` row stores the rule's "why" reason (e.g.
"rule R002: credential-access activity against the same account (alice)
followed external access") plus a role (`seed` for the first pair,
`member` for extensions). A member without a reason is impossible.

## Evidence store (spec 5.29)

`correlation_evidence` preserves, per member group, the fields that
mattered: family, phase, techniques, shared hosts/users/sources,
relationship signals and the rule reason - so a finding is auditable
months later without re-running the engine.

## Fingerprint (spec 5.6)

`sha256(type + sorted member ids + normalized edges)`. Two runs over the
same groups produce byte-identical fingerprints (determinism test); the
partial unique index guarantees at most one live finding per fingerprint
(concurrency test).

## API (spec 5.52-5.58)

| Endpoint | Returns |
|----------|---------|
| `GET /api/correlations` | list, filters: status, type, host, user, source_ip, destination_ip, technique, confidence_min, member_count_min, rule_id |
| `GET /api/correlations/{id}` | finding + edges |
| `GET /api/correlations/{id}/groups` | member groups with reasons/roles |
| `GET /api/correlations/{id}/alerts` | every member alert |
| `GET /api/correlations/{id}/evidence` | preserved evidence rows |
| `GET /api/correlations/{id}/timeline` | chronological member view |
| `GET /api/correlations/{id}/graph` | nodes + edges for visualization |
| `GET /api/correlations/{id}/audit` | lifecycle audit events |
| `GET /api/correlations/metrics` | compression + distribution metrics |
| `GET /api/correlations/evaluation` | labeled-corpus raw counts (spec 5.62) |
| `GET /api/correlations/rules` | the R001-R009 registry |

The API is read-only: correlation findings are engine-owned; there is no
analyst close endpoint (unlike Phase 4 groups) and no mutation surface.

## Metrics (spec 5.61)

`metrics()` reports finding counts, group reduction ratio
(1 - findings/groups), cross-host findings, median confidence, type and
rule distributions, and edge totals. Empty databases return zero-safe
values, never `None`/NaN.

## Evaluation (spec 5.62)

`evaluation_data.py` holds three hand-labeled scenarios
(c1-rdp-to-lateral, c2-unrelated-hosts, c3-temporal-only); the real engine
runs each and raw counts are reported: true/false positives,
true/false negatives, over/under-correlation. **No accuracy percentage is
ever fabricated** - raw counts only.