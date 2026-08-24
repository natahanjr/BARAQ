# BARAQ — Compliance & Export Control

**Document:** regulatory posture for selling BARAQ commercially
**Status:** informational; not legal advice. Consult a qualified lawyer in
your jurisdiction before the first sale.

---

## 1. Export control (dual-use)

Cybersecurity software can be classified as dual-use under the **Wassenaar
Arrangement** (Category 5 Part 2 — Information Security) in many
jurisdictions. BARAQ:

- implements cryptography (TLS, AES-256-GCM at rest, Ed25519 signing);
- performs intrusion/suspicious-behaviour detection and automated response
  actions (block/kill/quarantine commands to agents).

Depending on your jurisdiction (EU, US, and others), this may trigger
obligations such as:

1. **Registration** as a manufacturer/exporter of dual-use items
   (e.g. EU Dual-Use Regulation 2021/821; US EAR / BIS classification —
   likely a 5D002 classification review).
2. **Licence or licence exception** determination per export or per
   transfer to certain countries.
3. **De minimis / re-export** considerations when customers travel with
   the software.

**Actions:**
- [ ] Obtain an export-control classification for the software from your
      national authority or a qualified lawyer.
- [ ] Register as an exporter if required.
- [ ] Include the export/sanctions clause (see `LICENSE`, section 8) in
      every customer agreement.
- [ ] Screen customers against sanctions lists before shipping License Keys.

## 2. Data protection (GDPR)

BARAQ stores host telemetry (usernames, IP addresses, host names,
process/network activity) which can constitute **personal data**. Key
points:

- The **customer** (Licensee) is the data controller for the telemetry.
- The **vendor** (Licensor) acts as processor only for support/licensing.
- Implemented mitigations: 30-day event retention
  (`EVENT_RETENTION_DAYS`), role-based access, TLS in transit,
  AES-256-GCM at rest, audit trail, MFA.
- Required by the customer: DPAs where applicable, records of processing,
  and handling of data-subject requests (see `GDPR_PROCESSING.md`).

## 3. Encryption regulation (summary)

| Jurisdiction | Relevant regime | Practical effect |
|---|---|---|
| EU | Regulation 2021/821 (dual-use), GDPR (Art. 32 for encryption) | Export classification; encryption is a security measure under GDPR |
| US | EAR (5D002 / 5A002), CBP requirements | Classification review; no mass-market carve-out assumed — verify |
| Other | National cryptography/import rules | Verify for the customer's jurisdiction |

## 4. Product-safety and cyber-resilience

- **EU Cyber Resilience Act (CRA)** applies to products with digital
  elements placed on the EU market (mandatory from [date in force]).
  BARAQ v1.0 does not yet carry CE marking or the required vulnerability
  disclosure/documentation — plan CRA compliance before EU commercial
  distribution.
- Maintain a coordinated **vulnerability disclosure policy**
  (`SECURITY.md`), a security-contact mailbox, and an update channel
  (implemented: `/api/system/update/check`).

## 5. Selling process checklist

1. [ ] Complete `LICENSE`/EULA with company data and lawyer review.
2. [ ] Obtain export-control classification.
3. [ ] Register as exporter (if required by your jurisdiction).
4. [ ] Buy and apply an Authenticode code-signing certificate
      (`documentation/CODE_SIGNING.md`).
5. [ ] Run an independent penetration test (`documentation/PENTEST_BRIEF.md`)
      and record results in `SECURITY_AUDIT.md`.
6. [ ] Publish privacy/processing description (`GDPR_PROCESSING.md`) and
      define support tiers (`SUPPORT_SLA.md`).
7. [ ] Decide CRA/CE strategy for EU sales.
8. [ ] Define pricing and invoicing (not software work — business).
9. [ ] Provide trial keys via `scripts/license_gen.py`; activate per
      customer; rotate the license public/private key pair for real sales
      (see `backend/config.py` `LICENSE_PUBLIC_KEY`).

---

*This document is a working note, not legal advice.*