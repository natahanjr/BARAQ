# incidents/ — Phase 7 incident management (v2 boundary)

BOUNDARY — consumes DETECTIONs, ALERTs, BEHAVIOR GROUPs, CORRELATIONs,
and RISK; produces INCIDENTs. Creation is idempotent (one open incident
per deterministic fingerprint).

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
