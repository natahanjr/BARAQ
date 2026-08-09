# Deployment Hardening & Security Self-Audit

Part of the commercialization workstream. This document is the operational
checklist a reviewer (or external penetration tester) follows to validate a
SentinelSOC deployment, plus the current results of each control.

## Dependency Vulnerability Scan (current result)

| Stack | Tool | Result | Notes |
|---|---|---|---|
| Python (backend) | `python -m pip_audit -r requirements.txt --no-deps` | **0 vulnerabilities** | Run before every release |
| Node (frontend, prod deps) | `npm audit --omit=dev` | **0 vulnerabilities** | `react-router-dom` removed in favour of `react-router@8.3.0` |
| Node (frontend, full) | `npm audit` | **0 vulnerabilities** | Includes dev-only: vite 8 / esbuild patched |
| NPM advisories fixed | — | react-router open-redirect (GHSA-wrjc-x8rr-h8h6, CVE-2025-68470), RSC-mode CSRF (GHSA-qwww-vcr4-c8h2), esbuild devserver (GHSA-67mh), vite fs.deny bypass (GHSA-fx2h-pf6j-xcff) | |

How to reproduce:

```powershell
venv\Scripts\python -m pip install pip-audit
venv\Scripts\python -m pip_audit -r requirements.txt --no-deps
cd frontend
npm audit
```

---

## Hardening Controls Inventory

### 1. Transport (TLS)

- [x] HTTPS enforcement via `start.bat secure` (port 8443), `start.bat secure lan`
- [x] Self-signed SAN certificate (`scripts\gen_cert.ps1`) covering `localhost` + LAN IPv4
- [x] Certificate rotation via thumbprint file (`certs\sentinel.thumbprint`)
- [x] Session cookie forced `Secure` under TLS
- [x] Login brute-force rate limiting (5 failures / IP / 5 min)

### 2. Secrets

- [x] DPAPI-encrypted vault `secrets.dat` (Windows) — no plaintext secrets in `.env`
- [x] Dev API keys rejected when `SENTINEL_ALLOW_DEV_KEYS=0`
- [x] Encryption key for at-rest data (`SENTINEL_ENCRYPTION_KEY`) stored in vault
- [ ] Enforce vault on non-Windows (Linux container support) — open for Phase 3
- [ ] Key rotation workflow documented

### 3. Data at rest

- [x] AES-256-GCM envelope encryption for sensitive columns (audit detail, alert
  evidence, process command lines, email bodies, AI chat content)
- [x] Fields used in SQL `WHERE`/`GROUP BY` / hash keys intentionally left plaintext
- [x] `ENCRYPT_AT_REST` default ON (frozen in production builds)

### 4. Audit & logging

- [x] Tamper-evident SHA-256 hash chain on the audit log (`prev_hash`/`hash`)
- [x] Chain verification endpoint `GET /api/auth/audit/verify` + `verify_chain()`
- [x] Structured JSON logs (rotating file)
- [x] Syslog/SIEM forward via UDP or TCP (RFC3164/5424) with full audit payloads
- [x] Backfill of existing audit rows into the chain at startup (migration)

### 5. AuthN / AuthZ

- [x] API-key RBAC (analyst / admin), session tokens
- [x] Password hashing (scrypt/argon2 class, see `backend/auth.py`)
- [x] Account disable / role enforcement tests
- [x] TOTP 2FA (SC5a) — RFC 6238, challenge-based login, setup/confirm/disable endpoints
- [x] LDAP/SSO (SC5b) — bind + search adapter (`backend/ldap.py`), group→role mapping,
  auto-provisioning with unusable local password hash, audit of provision/sync/failures
- [x] OIDC (SC5c) — discovery/JWKS adapter (`backend/oidc.py`), RS256/ES256 signature
  verification, PKCE + nonce + state, clock-skew bounds, group→role mapping,
  auto-provisioning, signed one-time flow cookie, tests with a real RSA-signed id_token

### 6. Input validation & API hygiene

- [x] Enum + bounds validation on API inputs (pagination, limits, statuses)
- [x] All API endpoints (except health/docs) require auth
- [ ] CSRF considerations for state-changing endpoints (cookie sessions)
- [ ] Request size limits / body parsing caps

### 7. Host-level

- [x] `scripts\gen_cert.ps1` ACL-locks the private key to the current user
- [ ] Run the service as a dedicated non-admin principal (e.g. `sentinel` service account)
- [ ] Firewall exclusions documented (`start.bat lan` opens only port 8000/8443)
- [ ] Auto-update / managed-versioning channel

### 8. Monitoring & response

- [x] Every audit entry forwarded to SIEM for off-box integrity verification
- [ ] External backup of `database\sentinel.db` + `secrets.dat` (documented restore)
- [ ] Incidence-response runbook (link from `documentation\user_manual.md`)

---

## Self-audit against common OWASP Top-10 items

| OWASP | SentinelSOC status |
|---|---|
| A01 Broken Access Control | RBAC enforced on every `/api/*` route except health/docs; tests cover analyst-blocked user mutation |
| A02 Cryptographic Failures | TLS optional-but-secure; DPAPI vault; AES-256-GCM at rest; scrypt-style password hashing |
| A03 Injection | SQLAlchemy parameterized queries throughout; no raw SQL in app code |
| A04 Insecure Design | Rate-limited login; tamper-evident audit chain; dev keys blocked in prod |
| A05 Security Misconfig | Dev keys kill-switch; VITE proxy bound to localhost in dev; input enums |
| A08 Software & Data Integrity | pip-audit + npm audit clean before release; versioned release channel planned |

---

## Pen-test readiness checklist (handoff to an external party)

- [ ] Provide a test instance at `SENTINEL_ALLOW_DEV_KEYS=0` + TLS
- [ ] Provide read access to the audit-chain verify endpoint for integrity checks
- [ ] Share in/out-of-scope guidance from `SECURITY.md`
- [ ] Document the deployment topology (frontend served by backend static mount, DB isolation)
- [ ] Capture baseline `pip-audit` / `npm audit` output in this document at tag time

---

Status legend: `[x]` verified this session, `[ ]` queued for an explicit phase.

Last verified: 2026-08-09 (291+ tests passed: full `pytest tests` suite incl. OIDC SSO, TOTP MFA, CSRF/request-size, hold-out evaluation, ML v2 generalization, migrations, agent fleet, notification channels; `scripts/security_audit.py` green - pip-audit CVEs on `pip`/`pypdf` found and patched; `pip check` clean).

### Hold-out evaluation (external validity) - final verified numbers

`test_holdout_detects_unseen_attacks` (rules + ML, synthetic baseline): rule layer
recall 0.939 / precision 1.0 / FPR 0.0; ML layer recall 0.786 / FPR 0.0; hybrid
recall 0.951 / FPR 0.0. Every hold-out scenario (incl. the `ml_*` unseen C2 /
masquerade cases) is covered by at least one layer, and every `SCENARIO_RULE`
entry fires. Root-cause fix for the previously failing ML recall assertion:
`ml_*` hold-out scenarios are eventlog-based (event 4688), which
`MasqueradingRule`/`SuspiciousPowerShellRule` could not read; rules now scan
4688 rows (masquerading, powershell-with-powershell-filter), and a new
`c2_beacon` rule (T1071.001) covers the network C2 hold-out.