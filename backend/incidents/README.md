# incidents/ — Phase 7 incident management (v2 boundary)

BOUNDARY — consumes DETECTIONs, ALERTs, BEHAVIOR GROUPs, CORRELATIONs,
and RISK; produces INCIDENTs. Creation is idempotent (one open incident
per deterministic fingerprint).

**Fingerprint ownership (2026-09 fix).** `IncidentV2.fingerprint` is UNIQUE, so
one fingerprint is owned by one incident row for its whole life. The engine
therefore never re-inserts against a taken fingerprint:

- a non-terminal match is returned as-is (the alert joins the open incident);
- a **lapsed suppression** resumes the same incident and clears the
  suppression fields (audited as `INCIDENT_SUPPRESSION_EXPIRED`) rather than
  cloning a new incident;
- a terminal match (`CLOSED`/`SUPPRESSED`) is returned as-is — the analyst's
  decision stands, the fingerprint is never duplicated, and a distinct new
  event produces a distinct fingerprint, so "new activity does not reopen a
  closed incident" still holds.

The earlier implementation attempted the insert and handled the resulting
`IntegrityError` with `db.rollback()`, which **discarded the caller's whole
transaction**. It now uses a savepoint, so a lost race on the unique index
reuses the winning row and leaves the caller's pending work intact.

| Module | Contract |
|--------|----------|
| `contract.py` | States, severities, priorities, transitions, banned phrases, audit actions |
| `config.py` | SLA minutes, confidence formula weights, suppression limits |
| `models.py` | SQLAlchemy v2 tables and relationships |
| `registry.py` | Eligibility policies I001-I008 |
| `fingerprint.py` | Deterministic SHA256 fingerprinting |
| `eligibility.py` | Policy evaluation against incident context |
| `engine.py` | Create, transition, suppress, graph building |
| `lifecycle.py` | State transition validation |
| `investigation.py` | Notes, assignment, timeline |
| `evidence.py` | Evidence CRUD |
| `audit.py` | Audit trail |
| `metrics.py` | Aggregate metrics (no fake accuracy) |
| `evaluation.py` | Corpus runner |

Owns: `INCIDENT`. Emits: `INCIDENT` only.

NOT allowed: response/action execution, ML, SOAR.
