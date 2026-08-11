# BARAQ - Transport Security (TLS/HTTPS)

Three supported ways to expose BARAQ securely. Pick one; they are
mutually exclusive.

## Option A - Self-signed TLS served by the SOC itself (LAN / small team)

`start.bat` has a built-in HTTPS mode:

```bat
start.bat secure            :: HTTPS on 127.0.0.1:8443 (local only)
start.bat secure lan        :: HTTPS on 0.0.0.0:8443 + firewall rule
```

- `scripts\gen_cert.ps1` creates `certs\baraq.crt` + `certs\baraq.key`
  (RSA-2048, SANs for localhost + every local IPv4, valid 1 year, key locked
  to the current user via icacls).
- uvicorn binds with `--ssl-certfile`/`--ssl-keyfile`. The session cookie is
  forced to `Secure` automatically (`COOKIE_SECURE`), so auth cookies never
  travel over plain HTTP.
- Every analyst host should import `certs\baraq.crt` into "Trusted Root
  Certification Authorities" (certmgr.msc) to silence the browser warning.
- Agents must use `https://<server>:8443` as their `--server` URL.

The packaged executable honours the same config: `BARAQ_TLS=1` +
`BARAQ_TLS_CERT`/`BARAQ_TLS_KEY` make `run_server.py` serve HTTPS
(default port 8443).

## Option B - Reverse proxy with a real certificate (recommended for a domain)

Keep the SOC on `127.0.0.1:8001` (HTTP) and let Caddy or nginx terminate
TLS in front of it. Samples:

- `deployment\Caddyfile` - Caddy auto-provisions Let's Encrypt certs.
- `deployment\nginx-baraq.conf` - nginx with your CA certificate.

Both proxy websockets too, so the Command Center realtime channel works
behind the proxy. Agents point at `https://soc.example.com` with no port.

## Option C - SSH tunnel (quick remote access)

For occasional remote access without exposing anything:

```powershell
ssh -L 8001:127.0.0.1:8001 user@soc-host
# then open http://127.0.0.1:8001 locally
```

## Certificate rotation

- Self-signed certs expire after 1 year. Re-run `scripts\gen_cert.ps1`
  (it reuses the existing thumbprint until the cert changes) and restart the
  server.
- Let's Encrypt certs renew automatically via Caddy/certbot - no SOC action.

## Verification

```powershell
# From the server, after enabling TLS:
curl.exe -sk https://127.0.0.1:8443/api/health    # expect {"status":"ok",...}
# From an analyst workstation against the proxy:
curl.exe https://soc.example.com/api/health
```

## Hardening notes

- Prefer the proxy (Option B) for anything beyond a trusted LAN: the SOC's
  own TLS stack then never faces the internet, and HSTS headers are added.
- Never set `BARAQ_COOKIE_SECURE=0` while TLS is enabled - the app forces
  Secure cookies anyway.