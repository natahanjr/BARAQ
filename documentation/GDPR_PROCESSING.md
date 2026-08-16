# BARAQ — GDPR & Personal-Data Processing Description

**Purpose:** documentation the customer (data controller) needs for GDPR
compliance when deploying BARAQ. The vendor (licensor) processes personal
data only in the licensing/support context. The same description covers
**CCPA/CPRA** for California deployments (rights in section 5 map to both
regimes).

---

## 1. Roles

| Party | Role |
|---|---|
| Customer organisation deploying BARAQ | **Data controller** for all telemetry collected by BARAQ |
| BARAQ vendor (licensor) | **Processor** for licensing and support; **controller** for its own contact/billing data |

## 2. What personal data is processed

BARAQ collects Windows host telemetry on the customer's own machines:

| Category | Examples | Justification |
|---|---|---|
| Account identifiers | usernames, account names in login events (4624/4625) | security detection (brute force, credential abuse) |
| Network identifiers | IP addresses, host names, DNS queries, connection endpoints | anomaly detection, C2/exfiltration detection |
| System identifiers | process names/paths, command lines, service names | process-based detection, Sigma rules |
| File/email metadata | file paths, hashes, email sender/subject/attachment types | malware/phishing detection |

Sensitive data (special categories, Art. 9 GDPR) is not intentionally
collected; command lines and email subject lines may occasionally contain
content of that nature — pseudonymisation guidance in section 6.

## 3. Legal bases

For the customer as controller, the typical bases are:

- **Art. 6(1)(f) — legitimate interest**: protection of the organisation's
  information systems against intrusion, theft and abuse (balancing test
  documented by the controller);
- **Art. 6(1)(b)/(c)** where employment or legal obligations apply
  (e.g. security-monitoring clauses in employment contracts or sector
  regulation).

The controller must perform and document its own legitimate-interest
assessment.

## 4. Built-in mitigations (implemented)

- **Retention**: events retained 30 days by default
  (`EVENT_RETENTION_DAYS`); retention job prunes older events. The chained
  audit trail ages out on its own regulatory window
  (`BARAQ_AUDIT_RETENTION_DAYS`, default 365).
- **Access control**: RBAC (admin/analyst), TOTP MFA enforcement for
  admins, API-key scopes.
- **In transit**: TLS (production gate requires `BARAQ_TLS=1`).
- **At rest**: AES-256-GCM envelope encryption for sensitive columns
  (command lines, email bodies, audit details, AI chat); DPAPI vault for
  secrets.
- **Audit**: tamper-evident SHA-256 chain; forwarding to the customer's
  SIEM.
- **Minimisation**: normalizer keeps only fields needed for detection.
- **Anonymization**: built-in PII masking (deterministic SHA-256 tokens)
  for lawful secondary use — `GET /api/compliance/export` (admin).

## 5. Data-subject rights support

The controller must be able to honour rights (access, rectification,
erasure, restriction, portability). Practical support in BARAQ:

- **Access / DSAR (Art. 15 / CCPA 1798.100)**: one-shot package of every
  record about a subject:
  ```
  GET /api/compliance/dsar?email=<subject>      # admin, API key
  ```
  Returns the account row, all audit-chain entries by that actor, all
  events for that user and any alerts mentioning the subject. Deliver the
  package securely to the requester and delete it after fulfilment.
- **Erasure (Art. 17 / CCPA 1798.105)**: delete the events for a subject:
  ```sql
  DELETE FROM events WHERE account_name = '<subject>' OR user = '<subject>';
  -- repeat for processes / network_connections / dns_queries / http_requests
  -- / emails / file_scans / vuln_findings as applicable
  ```
  (Document this query in the controller's records of processing.)
- **Anonymized export / portability**: PII-free dataset for analytics:
  ```
  GET /api/compliance/export?hours=24&org=<org>   # admin, API key
  ```
- **Compliance report (Art. 30 / CCPA record-keeping)**: data inventory,
  retention windows and anonymization posture:
  ```
  GET /api/compliance/report                        # admin, API key
  GET /api/compliance/audit/retention               # admin, API key
  ```
- **Objection (Art. 21)**: relied on the legitimate-interest basis — the
  controller evaluates objections case by case.

## 6. Pseudonymisation guidance

Before using telemetry in research, theses, or publications:

- Replace account names with opaque identifiers (user-A, user-B).
- Truncate/anonymise IP addresses (e.g. 192.168.x.x or last octet 0).
- Remove host names or map them to a code.
- Strip command lines that may contain personal content (names, file
  paths with personal data) from exported datasets.
- The hold-out evaluation's negative class already uses real host
  telemetry — export only aggregated metrics, never raw telemetry, for
  publication.

## 7. Processor obligations (vendor side)

Where the vendor acts as processor (support access to a customer's
deployment):

- Process only on documented instructions.
- Sign a **Data Processing Agreement (DPA)** with each customer before any
  support access.
- Implement confidentiality, subprocessor notice (none used for telemetry),
  breach notification assistance, and deletion-on-termination.
- Access for support should use the customer's own admin account, under
  their supervision, with the audit chain running.

## 8. Breach handling

- The controller is responsible for notifying the supervisory authority
  (72 h, Art. 33) and data subjects (Art. 34) where required.
- The vendor supports this by: documented retention (30 days), audit
  chain, SIEM forwarding, and the incident-response notes in
  `documentation/user_manual.md`.

---

*Not legal advice. Have the controller's DPO or counsel review this
description before deployment.*