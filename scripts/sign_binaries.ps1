# BARAQ — Binary Signing Helper

Signs the release artifacts (installer, server exe, agent exe) with an
Authenticode certificate and verifies each signature. Intended to run on
the build machine after `build_release.ps1` — or automatically via the
BARAQ_SIGN_* environment variables (see build_release.ps1).

Usage:
    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign_binaries.ps1 `
        -CertPfx C:\secure\code-signing.pfx -CertPassword "pfxpass" `
        -TimestampUrl "http://timestamp.digicert.com"

    powershell -NoProfile -ExecutionPolicy Bypass -File scripts\sign_binaries.ps1 `
        -StoreSubject "BARAQ Signing Co"

Requirements: Windows SDK signtool.exe on PATH (or in the standard
Windows Kits location).
#>
param(
    [string]$CertPfx,
    [string]$CertPassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$StoreSubject
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"

# ---------------------------------------------------------------- signtool
$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if (-not $signtool) {
    $kit = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" `
        -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $kit) {
        throw "signtool.exe not found. Install the Windows SDK (winget install Microsoft.WindowsSDK.10.0.26100)."
    }
    $signtool = $kit.FullName
} else {
    $signtool = $signtool.Source
}

# ------------------------------------------------------------- certificate
if ($StoreSubject) {
    $signArgs = @("/sha1", $null)  # replaced below by subject resolution
    $cert = Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -match $StoreSubject } | Select-Object -First 1
    if (-not $cert) {
        throw "No certificate matching subject '$StoreSubject' found in the store."
    }
    $subjectFlag = @("/sha1", $cert.Thumbprint)
} elseif ($CertPfx) {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $CertPfx, $CertPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
    )
    $installDir = Join-Path $env:LOCALAPPDATA "BARAQ\signing"
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $thumb = $cert.Thumbprint
    $import = Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint -eq $thumb } | Select-Object -First 1
    if (-not $import) {
        Import-PfxCertificate -FilePath $CertPfx -CertStoreLocation Cert:\CurrentUser\My `
            -Password (ConvertTo-SecureString $CertPassword -AsPlainText -Force) | Out-Null
        Write-Host "installed cert $thumb into CurrentUser\My"
    }
    $subjectFlag = @("/sha1", $thumb)
} else {
    throw "Provide either -CertPfx/-CertPassword or -StoreSubject."
}

# ---------------------------------------------------------------- artifacts
$artifacts = @()
foreach ($f in @(
    (Join-Path $Dist "BARAQ-Setup-1.0.0.exe"),
    (Join-Path $Dist "BARAQ\BARAQ.exe"),
    (Join-Path $Dist "BARAQAgent.exe")
)) {
    if (Test-Path $f) { $artifacts += $f }
}
if ($artifacts.Count -eq 0) {
    throw "No artifacts found under $Dist - run scripts\build_release.ps1 first."
}

# ------------------------------------------------------------------- sign
foreach ($file in $artifacts) {
    Write-Host "signing $file"
    $args = @(
        "sign", "/fd", "SHA256",
        "/tr", $TimestampUrl, "/td", "SHA256",
        $subjectFlag,
        $file
    )
    & $signtool $args
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $file (exit $LASTEXITCODE)" }
    $verify = & $signtool "verify" "/pa" "/v" $file 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "signature verification failed for $file"
    }
    Write-Host "  OK - verified ($($verify | Select-String 'Signer Certificate Chain' | Select-Object -First 1))"
}
Write-Host "All artifacts signed and verified."