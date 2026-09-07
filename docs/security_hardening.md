# BARAQ - Security Hardening Checklist

Operational checklist for taking a BARAQ deployment from "dev box"
to "server worth depending on". Every item links to the tooling/runbook
that implements it. Run `scripts\security_audit.py` to auto-verify most of
the static items; the list below is the full operational picture.

## 1. Transport (TLS)

- [ ] Use HTTPS everywhere: `start.bat secure` (self-signed LAN) or a
      reverse proxy with a real cert (`deployment\Caddyfile`,
      `deployment\nginx-baraq.conf`). See `documentation\tls_https.md`.
- [ ] Import `certs\baraq.crt` into client trusted roots when using the
      self-signed option (`scripts\import_cert.ps1` per client, or
      `-Machine` with admin for all users).
- [ ] Agents must point at the HTTPS URL (`--server https://...`), not HTTP.
- [ ] Never set `BARAQ_COOKIE_SECURE=0` under TLS (the app forces Secure
      cookies anyway when TLS is on).

## 2. Authentication & access

- [ ] TOTP 2FA enabled for every admin: Users & Audit -> Set Up 2FA.
      (Flow: `/api/auth/mfa/setup|confirm|verify|disable`.)
- [ ] No shared accounts; one analyst account per person (analyst role,
      no admin).
- [ ] Agent keys: provision/revoke only via `scripts\provision_agent.py`
      (never hand-edit the vault). Rotate on suspicion.
- [ ] Keep `admin` only for bootstrap; create named admins.
- [ ] Login throttling is on by default (429 after repeated failures) - do
      not disable.

## 3. Secrets & keys

- [ ] `secrets.dat` (DPAPI vault) is present and never committed; `.env`
      stays out of git (both are gitignored).
- [ ] API keys/agent keys live in the vault, not in code, not in chat.
- [ ] Rotate the admin password and API keys after first deployment.

## 4. Availability & data protection

- [ ] Run as a Windows service (NSSM preferred):
      `scripts\install_service.ps1 install` (`documentation\windows_service.md`).
- [ ] Automated daily backups: `scripts\db_backup.py backup --keep 14`
      scheduled at 03:00 (see `documentation\backup_restore.md`).
- [ ] Weekly `scripts\db_backup.py verify` + a quarterly test restore.
- [ ] Schema migrations: `venv\Scripts\python scripts\migrate_db.py` on every
      upgrade (`documentation\migrations.md`).
- [ ] Exactly one server instance: the DB advisory lock disables the second
      instance's scheduler automatically (G4).

## 5. Monitoring & alerting

- [ ] Configure at least one out-of-band alert channel in `backend\config.py`:
      `BARAQ_WEBHOOK_URL` (Slack/Teams aware), `BARAQ_SMTP_*`, and/or
      `BARAQ_TELEGRAM_BOT_TOKEN` + `BARAQ_TELEGRAM_CHAT_ID`.
      `NOTIFY_MIN_SEVERITY` defaults to high.
- [ ] Verify the channel with a real high/critical alert (or the test
      harness in `tests\test_notify.py`).
- [ ] SMTP uses STARTTLS by default - keep `BARAQ_SMTP_STARTTLS=1`.

## 6. Supply chain

- [ ] `venv\Scripts\python -m pip_audit -l` (or `scripts\security_audit.py`)
      clean before any release; pin new direct deps in requirements.txt.
- [ ] `npm audit` clean in `frontend\`.
- [ ] Verify `pip check` clean after every install.

## 7. API hardening (roadmap 5.3)

Applied automatically by `backend\main.py` middleware; verify with
`scripts\security_audit.py` and `tests\test_hardening.py`.

- [ ] Security headers on every response: `X-Content-Type-Options: nosniff`,
      `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
      `Permissions-Policy` (camera/mic/geolocation off), a restrictive
      `Content-Security-Policy` (`default-src 'none'`, `frame-ancestors 'none'`),
      and `Strict-Transport-Security` (180 days). Disable with
      `BARAQ_SECURITY_HEADERS=0` only when a reverse proxy emits its own.
- [ ] API rate limiting: fixed-window per client (API key, else client IP),
      `BARAQ_API_RATE_LIMIT=600` / burst `BARAQ_API_RATE_BURST=900` per minute.
      Exceeding it returns `429` + `Retry-After` before auth ever runs.
      `/api/health` and `/api/auth/login` are exempt (login has its own
      throttler in `backend\api\auth.py`).
- [ ] IP ACLs: `BARAQ_API_IP_WHITELIST=192.168.0.0/16,10.0.0.0/8` restricts
      API access to those CIDRs (403 otherwise); `BARAQ_API_IP_BLOCKLIST`
      denies specific networks first. Agent ingest (`/api/ingest`,
      `/api/commands/`) is subject to the same ACLs - keep agents inside the
      whitelisted ranges.
- [ ] Request size cap stays on: `BARAQ_MAX_REQUEST_BYTES` (16 MiB default,
      413 response).
- [ ] CI runs `pip_audit` (dependency scan) on every push; the release
      checklist below plus the `docker-image` job publish images only from
      version tags.

## 8. Every release

1. `scripts\db_backup.py backup --keep 14`
2. `scripts\security_audit.py`  (expect exit 0)
3. `venv\Scripts\python -m pytest`  (expect all green)
4. Restart the service; confirm `http(s)://host/api/health` reports
   `status:"ok"` and the service stays up after a reboot.

See also `SECURITY_AUDIT.md` (baseline evidence table) and `SECURITY.md`
(vulnerability reporting policy).