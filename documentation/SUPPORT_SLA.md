# BARAQ — Support & Service-Level Agreement (Template)

**Status:** template for commercial launch. Fill in the [brackets], align
prices with your business plan, and attach to each customer order.

---

## 1. Parties

- Licensor: [Name / Company], contact [email], response address [address]
- Licensee: [Customer name], contact [email]

## 2. Covered software

BARAQ server console + agent, version [1.0.x], license keys issued under
`LICENSE`. Support covers the Software as delivered; it does not cover the
customer's network, OS, or third-party modifications.

## 3. Support tiers

| Tier | Features | Response target | Availability |
|---|---|---|---|
| **Standard** (included with license) | Community knowledge base, security advisories, update channel, bug fixes in the next release | Best effort | Business hours [TZ] |
| **Priority** | Standard + email support, hotfixes, remote diagnostic sessions | 1 business day | Business hours [TZ] |
| **Critical/24x7** | Priority + phone/chat, 24/7 incident triage | 1 hour (critical) / 4 hours (high) | 24x7 |

Severity definitions:

| Severity | Definition |
|---|---|
| Critical | Service down, security control bypass, data loss |
| High | Major feature broken, workaround exists |
| Medium | Minor issue, workaround exists |
| Low | Cosmetic / documentation |

## 4. Responsibilities

**Licensor:**
- maintain the update channel (manifest + signed installer);
- publish security advisories for confirmed vulnerabilities with
  recommended mitigations (see `SECURITY.md`);
- provide fixes via the next release (or hotfix at Priority/Critical tiers).

**Licensee:**
- keep the Software updated and the console reachable for support;
- provide logs, steps to reproduce, and evidence;
- not attempt to remove the license mechanism or bypass controls;
- maintain its own backups (see `documentation/backup_restore.md`).

## 5. Exclusions

Support does not cover: failures caused by customer modifications,
third-party software, OS corruption, natural events, or use outside the
license terms; downtime during scheduled maintenance (announced [5]
business days ahead); free/trial deployments.

## 6. Credits

If the Licensor misses a response target for a Critical incident, the
Licensee earns a service credit of [5]% of the monthly support fee per
incident, capped at [20]% in any calendar quarter, applied against the
next invoice.

## 7. Term, renewal, termination

Support term runs with the license term. Either party may terminate on
[30] days' written notice. Fees are non-refundable except as provided in
section 6. Continued use after license expiry requires renewal.

---

*Accepted — Licensor: ______  Date: ______   Licensee: ______  Date: ______*