# ===========================================================================
#  BARAQ - TLS certificate generator (self-signed, SAN localhost+LAN IP)
#  Usage: powershell -ExecutionPolicy Bypass -File scripts\gen_cert.ps1
#  Output: certs\baraq.crt (PEM cert), certs\baraq.key (PEM key)
#  The certificate is kept in the CurrentUser personal store so clients can
#  import it as a trusted root (see instructions printed at the end).
# ===========================================================================
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$certDir = Join-Path $root "certs"
New-Item -ItemType Directory -Path $certDir -Force | Out-Null

$certFile = Join-Path $certDir "baraq.crt"
$keyFile = Join-Path $certDir "baraq.key"
$pfxFile = Join-Path $certDir "baraq.pfx"
$thumbFile = Join-Path $certDir "baraq.thumbprint"

# Gather SAN names: localhost + all IPv4 addresses on this machine
$sans = @("localhost", "127.0.0.1", "::1")
Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" } |
    ForEach-Object { $sans += $_.IPAddress }
$sans = $sans | Select-Object -Unique

Write-Host "Generating self-signed certificate for: $($sans -join ', ')"

# Reuse the existing certificate if the thumbprint file matches the store.
$thumbprint = ""
if (Test-Path $thumbFile) { $thumbprint = (Get-Content $thumbFile).Trim() }
$cert = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $thumbprint } | Select-Object -First 1

if (-not $cert) {
    $ipList = @("127.0.0.1", "::1")
    $ipList += Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.254.*" -and $_.IPAddress -notlike "127.*" } |
        ForEach-Object { $_.IPAddress }
    $ipList = $ipList | Select-Object -Unique

    $dn = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName("CN=localhost")
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest(
        $dn, $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $sanBuilder = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    $sanBuilder.AddDnsName("localhost")
    foreach ($ip in $ipList) { $sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse($ip)) }
    $req.CertificateExtensions.Add($sanBuilder.Build())
    $ekuOids = New-Object System.Security.Cryptography.OidCollection
    $ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1")) | Out-Null
    $ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.2")) | Out-Null
    $req.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($ekuOids, $false)))
    $req.CertificateExtensions.Add(
        (New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(
            ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
             [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment), $false)))

    $cert = $req.CreateSelfSigned(
        [DateTimeOffset]::Now.AddDays(-1),
        [DateTimeOffset]::Now.AddYears(1))
    $thumbprint = $cert.Thumbprint
    Set-Content -Path $thumbFile -Value $thumbprint
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        "My", [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    $store.Close()
    Write-Host "  New certificate created (thumbprint $thumbprint)."
} else {
    Write-Host "  Reusing existing certificate (thumbprint $thumbprint)."
}

# Export PEM certificate (wrap base64 at 64 chars exactly)
$b64 = [Convert]::ToBase64String($cert.RawData)
$b64Wrapped = (($b64 -replace "(.{64})", "`$1`n") -replace "`n$", "")
$certPem = "-----BEGIN CERTIFICATE-----`n" + $b64Wrapped + "`n-----END CERTIFICATE-----`n"
Set-Content -Path $certFile -Value $certPem -Encoding Ascii

# Export PFX then extract the private key with OpenSSL (falls back to .NET export)
$pfxPass = [System.Guid]::NewGuid().ToString("N")
[System.IO.File]::WriteAllBytes($pfxFile, $cert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPass))
$env:OPENSSL_CONF = ""
& openssl pkcs12 -in $pfxFile -nodes -passin pass:$pfxPass -nocerts -out $keyFile 2>$null
if (-not (Test-Path $keyFile) -or (Get-Item $keyFile).Length -eq 0) {
    # Fallback: .NET PKCS#1 export (no OpenSSL required)
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    $pkcs1 = $rsa.ExportRSAPrivateKey()
    $keyB64 = [Convert]::ToBase64String($pkcs1)
    $keyWrapped = (($keyB64 -replace "(.{64})", "`$1`n") -replace "`n$", "")
    $keyPem = "-----BEGIN RSA PRIVATE KEY-----`n" + $keyWrapped + "`n-----END RSA PRIVATE KEY-----`n"
    Set-Content -Path $keyFile -Value $keyPem -Encoding Ascii
}
Remove-Item $pfxFile -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $keyFile)) { throw "private key export failed" }

# Lock down permissions: current user only (domain\user form avoids icacls
# mis-parsing a bare username as a domain).
$aclGrant = "${env:USERDOMAIN}\${env:USERNAME}:(F)"
& icacls $keyFile /inheritance:r /grant $aclGrant | Out-Null
& icacls $certFile /inheritance:r /grant $aclGrant | Out-Null

Write-Host ""
Write-Host "  Certificate : $certFile"
Write-Host "  Key         : $keyFile"
Write-Host "  SANs        : $($sans -join ', ')"
Write-Host "  Expires     : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Thumbprint  : $thumbprint"
Write-Host ""
Write-Host "Import baraq.crt into 'Trusted Root Certification Authorities'"
Write-Host "of each client browser to remove the security warning:"
Write-Host "  powershell -ExecutionPolicy Bypass -File scripts\import_cert.ps1"
