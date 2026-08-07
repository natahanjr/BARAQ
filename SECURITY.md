# Security Policy

SentinelSOC is designed for production use in security-sensitive environments
(enterprise SOC teams, universities, financial institutions). We take the
security of the platform and its deployments seriously and follow a
coordinated disclosure process.

## Supported Versions

| Version | Status |
|---|---|
| Latest release (tagged `v*` on GitHub) | Actively supported |
| `main` branch | Pre-release — bugs fixed on best effort |
| Older releases | No longer maintained — upgrade required |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately to the maintainers:

- **Email:** `security@sentinel-soc.example` (replace with the real maintainer address)
- **PGP:** fingerprint `A1B2 C3D4 E5F6 7890 ...` (key published on the repo; replace)

Include as much of the following as possible:

1. **Product & version** — release tag / commit hash / `.exe` build date
2. **Environment** — OS version, deployment mode (local / `--lan` / TLS), browser
3. **Vulnerability class** — e.g. auth bypass, injection, sensitive data exposure, SSRF
4. **Steps to reproduce** — minimal, deterministic, no sensitive data
5. **Impact assessment** — what an attacker gains, whether it is exploitable remotely
6. **Suggested fix** (optional)

If you believe the issue is **actively exploited or contains sensitive customer
data**, mark the email subject `[CRITICAL]` and, if possible, send a PGP-encrypted
message.

## Response Timeline

| Phase | Target |
|---|---|
| Acknowledgement | Within **2 business days** |
| Triage & severity assessment | Within **5 business days** |
| Fix + regression test | **Critical/High**: 7 days · **Medium**: 30 days · **Low**: next release |
| Coordinated public disclosure | **90 days** after the fix ships (sooner with reporter consent) |

The severity follows CVSS v3.1. Reporting is tracked; you will be kept informed
of progress at every milestone.

## Coordinated Disclosure Process

1. Reporter sends a private report (above).
2. Maintainers acknowledge, reproduce, and triage.
3. A fix is developed with a regression test and backported to all supported versions.
4. A security advisory is drafted (severity, affected versions, mitigation).
5. The fix is released; the advisory is published **after** customers can patch.
6. The reporter is credited (unless anonymity is requested).

We ask reporters to withhold public disclosure until the fix is released, and we
commit to moving quickly enough that this is never an unreasonable ask.

## Scope

In scope:

- The FastAPI backend (`backend/`), REST API, authentication & RBAC
- The React dashboard (`frontend/`) and its API integration
- The Windows collectors, agent (`scripts/agent.py`) and fleet ingest
- The self-contained `.exe` packaging (`scripts/build_exe.bat`)
- The DPAPI secret vault, TLS handling, encryption-at-rest, audit hash chain

Out of scope:

- Vulnerabilities in third-party dependencies that are already fixed upstream —
  report them upstream; dependency advisories are tracked in our release notes
- Issues caused by misconfiguration of a deployment (documented in the user manual)
- Phishing/social-engineering of operators, physical security of the host machine
- Unsolicited mass automated scanning; report one issue per report

## Security Hardening Summary (current)

Implemented and verified in the current codebase:

- **TLS everywhere** — optional HTTPS (`start.bat secure`), self-signed SAN
  certificate generation with rotation, `Secure` session cookies under TLS
- **Encryption at rest** — AES-256-GCM envelope encryption for sensitive fields
  (audit details, alert evidence, process command lines, email bodies, AI chat
  content); key protected by the Windows DPAPI vault
- **Secret management** — no plaintext secrets in `.env`; DPAPI-encrypted
  `secrets.dat` vault; dev keys rejected in production (`SENTINEL_ALLOW_DEV_KEYS=0`)
- **Tamper-evident audit log** — SHA-256 hash-chained audit entries with an
  integrity verification endpoint (`GET /api/auth/audit/verify`)
- **Centralized logging** — structured JSON logs with optional syslog (UDP/TCP)
  forwarding for SIEM ingestion
- **Brute-force protection** — login rate limiting (5 failures / IP / 5 minutes)
- **Input validation** — enum/bounds validation on API inputs; pagination limits

## Dependencies

We track vulnerabilities in dependencies (`pip-audit`/`npm audit`) before every
release. See the release notes for the advisory list of each version.

## Thanks

We thank the researchers who report responsibly and help make SentinelSOC
safer for everyone.
