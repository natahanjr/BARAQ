# BARAQ TLS/HTTPS Setup Guide

## Quick Start (Self-Signed for LAN)

### Option 1: Generate self-signed certificate (Windows)

```powershell
# Run as Administrator
cd F:\My Project\Baraq

# Generate self-signed cert (valid 1 year)
$cert = New-SelfSignedCertificate `
    -DnsName "192.168.1.5", "localhost" `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(1) `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256

# Export to PFX file
$password = ConvertTo-SecureString -String "BaraqTLS2026!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "certs\baraq.pfx" -Password $password

# Export public key for agents
Export-Certificate -Cert $cert -FilePath "certs\baraq.crt"
```

### Option 2: Use nginx reverse proxy with Let's Encrypt (production)

See `config/nginx/baraq.conf` for the full nginx configuration.

### Option 3: Use IIS reverse proxy (Windows Server)

1. Install IIS with ARR (Application Request Routing)
2. Import the PFX certificate
3. Configure reverse proxy to forward to localhost:8001

## Enable TLS on BARAQ

Add to `.env`:
```
BARAQ_TLS=1
BARAQ_TLS_CERTFILE=certs\baraq.pfx
BARAQ_TLS_KEYFILE=
BARAQ_TLS_PASSWORD=BaraqTLS2026!
```

Or run with plaintext in dev:
```
BARAQ_ALLOW_PLAINTEXT_PROD=1
```

## Agent Communication

When TLS is enabled, agents must connect via HTTPS:
```powershell
.\agent.ps1 -Server https://192.168.1.5:8443 -Key YOUR-AGENT-KEY
```

## Firewall Rules

```powershell
# Allow HTTPS through Windows Firewall
netsh advfirewall firewall add rule name="BARAQ HTTPS" dir=in action=allow protocol=TCP localport=8443
```
