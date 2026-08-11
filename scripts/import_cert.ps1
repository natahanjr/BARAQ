# ===========================================================================
#  BARAQ - import certs\baraq.crt into a client's Trusted Root store
#  Usage:   powershell -ExecutionPolicy Bypass -File scripts\import_cert.ps1
#           powershell -ExecutionPolicy Bypass -File scripts\import_cert.ps1 -Machine
#  Default: CurrentUser Root store (no admin required, silences the browser
#           warning for the current user). -Machine installs into the
#           LocalMachine Root store (affects all users; requires admin).
#  Idempotent: a thumbprint match skips re-import (safe to re-run after each
#  cert rotation).
# ===========================================================================
param(
    [string]$Path,
    [switch]$Machine
)
$ErrorActionPreference = "Stop"

if (-not $Path) {
    $Path = Join-Path (Split-Path -Parent $PSScriptRoot) "certs\baraq.crt"
}
if (-not (Test-Path $Path)) {
    throw "Certificate not found: $Path`nRun scripts\gen_cert.ps1 first to generate certs\baraq.crt."
}

$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($Path)

if ($Machine) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "The -Machine store requires an elevated PowerShell (run as Administrator)."
    }
    $storePath = "Cert:\LocalMachine\Root"
} else {
    $storePath = "Cert:\CurrentUser\Root"
}

$existing = Get-ChildItem $storePath -ErrorAction SilentlyContinue |
    Where-Object { $_.Thumbprint -eq $cert.Thumbprint } |
    Select-Object -First 1

if ($existing) {
    Write-Host "  baraq.crt already trusted ($($cert.Subject)). Nothing to do."
    exit 0
}

Import-Certificate -FilePath $Path -CertStoreLocation $storePath | Out-Null
Write-Host "  Imported baraq.crt into $storePath"
Write-Host "  Subject   : $($cert.Subject)"
Write-Host "  Thumbprint: $($cert.Thumbprint)"
Write-Host "  Expires   : $($cert.NotAfter.ToString('yyyy-MM-dd'))"
Write-Host "  Browser warning for https://<soc-host>:8443 is now silenced."
Write-Host "  (Restart open browsers; the TLS cache may need a reload.)"
