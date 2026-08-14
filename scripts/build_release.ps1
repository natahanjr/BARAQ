# BARAQ release build: server folder-build, agent exe, fleet package.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_release.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_release.ps1 -SkipAgent
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_release.ps1 -SkipServer
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_release.ps1 -SkipFrontend
#
# Produces:
#   dist\BARAQ\                      server (folder layout, console)
#   dist\BARAQAgent.exe                 fleet agent (single file)
#   dist\baraq-agent-package\           agent + sample config + install guide
#   dist\.env                              sealed first-run credential seed
#   dist\BARAQ-Installer.exe         Inno Setup installer (if ISCC found)
param(
    [switch]$SkipFrontend,
    [switch]$SkipServer,
    [switch]$SkipAgent,
    [switch]$SkipInstaller
)
$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root "venv\Scripts\python.exe"
$Dist   = Join-Path $Root "dist"

function Step([string]$Label) { Write-Host "`n=== $Label ===" }

function Ensure-PyInstaller {
    & $Python -c "import PyInstaller" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  installing PyInstaller ..."
        & $Python -m pip install --quiet pyinstaller
        if ($LASTEXITCODE -ne 0) { throw "pip install pyinstaller failed" }
    }
}

function Build-Frontend {
    if (Test-Path (Join-Path $Root "frontend\dist\index.html")) { return }
    Write-Host "  building dashboard (frontend\dist missing) ..."
    Push-Location (Join-Path $Root "frontend")
    try { & npm install --silent; & npm run build } finally { Pop-Location }
    if ($LASTEXITCODE -ne 0) { throw "npm build failed" }
}

function New-SeedEnv {
    # Sealed first-run credentials embedded in the executables - the product
    # boots with these on every machine (preferred over random generation).
    # The admin password is the well-known default: fresh installs seed the
    # account with it and the console forces a change (must_change_password)
    # before it can be used.
    $envFile = Join-Path $Dist ".env"
    if (Test-Path $envFile) { return }
    New-Item -ItemType Directory -Path $envFile.Substring(0, $envFile.LastIndexOf("\")) -Force | Out-Null
    $adminKey = "baraq-admin-" + ([System.Guid]::NewGuid().ToString("N").Substring(0, 20))
    $analystKey = "baraq-analyst-" + ([System.Guid]::NewGuid().ToString("N").Substring(0, 20))
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 32
    $rng.GetBytes($bytes)
    $secret = [System.BitConverter]::ToString($bytes).Replace("-", "")
    $pass = "baraqadmin"
    @(
        "BARAQ_ADMIN_PASSWORD=$pass",
        "BARAQ_API_KEYS=""{""$adminKey"":""admin"",""$analystKey"":""analyst""}""",
        "BARAQ_TOKEN_SECRET=$secret"
    ) | ForEach-Object { $_.ToString() } | Set-Content -Path $envFile -Encoding UTF8
    # Strip the UTF-8 BOM that PS5 Set-Content -Encoding UTF8 adds (the seed
    # loader must see clean keys).
    $bytes = [System.IO.File]::ReadAllBytes($envFile)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        [System.IO.File]::WriteAllBytes($envFile, $bytes[3..($bytes.Length-1)])
    }
    Write-Host "  seed written to dist\.env (default password baraqadmin; change forced on first login)"
}

Ensure-PyInstaller
New-SeedEnv

if (-not $SkipFrontend) { Step "frontend"; Build-Frontend }

if (-not $SkipServer) {
    Step "server (onedir build via baraq.spec)"
    & $Python -m PyInstaller --noconfirm --clean `
        --distpath $Dist --workpath (Join-Path $Root "build\pyinstaller") `
        (Join-Path $Root "baraq.spec")
    if ($LASTEXITCODE -ne 0) { throw "server build failed" }
}

if (-not $SkipAgent) {
    Step "agent (onefile build via agent.spec)"
    & $Python -m PyInstaller --noconfirm --clean `
        --distpath $Dist --workpath (Join-Path $Root "build\pyinstaller") `
        (Join-Path $Root "agent.spec")
    if ($LASTEXITCODE -ne 0) { throw "agent build failed" }

    Step "fleet package"
    $pkg = Join-Path $Dist "baraq-agent-package"
    New-Item -ItemType Directory -Path $pkg -Force | Out-Null
    Copy-Item (Join-Path $Dist "BARAQAgent.exe") $pkg -Force
    @{
        server   = "https://<central-host>:8443"
        key      = "baraq-agent-<hostname>"
        interval = 15
        tls_ca   = "certs\baraq.crt"
        no_verify = $false
    } | ConvertTo-Json | Set-Content (Join-Path $pkg "agent.config.sample.json") -Encoding UTF8
    @'
BARAQ fleet agent package - deploy on every host you want monitored:

1. Copy this folder to the target host (any location).
2. Open an admin PowerShell on the target host and register the agent:

     .\BARAQAgent.exe --install --server https://<central>:8443 --key baraq-agent-<hostname> --tls-ca certs\baraq.crt

   (without --tls-ca the agent verifies against the Windows store; use it to
    pin the central server's self-signed certificate)

3. The agent starts immediately and re-starts at every logon automatically.
   Its config lives in %LOCALAPPDATA%\BARAQAgent\agent.config.json,
   logs go to %LOCALAPPDATA%\BARAQAgent\agent.log.
4. Remove later with:

     .\BARAQAgent.exe --uninstall --purge
'@ | Set-Content (Join-Path $pkg "INSTALL.txt") -Encoding UTF8
    Write-Host "  fleet package at $pkg"
}

if (-not $SkipInstaller) {
    Step "installer (Inno Setup)"
    & (Join-Path $PSScriptRoot "build_installer.ps1")
}

Step "code signing (optional)"
$pfx = $env:BARAQ_SIGN_CERT_PFX
$pass = $env:BARAQ_SIGN_CERT_PASS
$ts = $env:BARAQ_SIGN_TIMESTAMP
$storeSubj = $env:BARAQ_SIGN_STORE_SUBJECT
if ($pfx -or $storeSubj) {
    $signArgs = @()
    if ($pfx) {
        $signArgs += @("-CertPfx", $pfx)
        if ($pass) { $signArgs += @("-CertPassword", $pass) }
    } else {
        $signArgs += @("-StoreSubject", $storeSubj)
    }
    if ($ts) { $signArgs += @("-TimestampUrl", $ts) }
    & (Join-Path $PSScriptRoot "sign_binaries.ps1") @signArgs
} else {
    Write-Host "  no certificate configured (BARAQ_SIGN_CERT_PFX / BARAQ_SIGN_STORE_SUBJECT) - artifacts unsigned"
}

Write-Host "`nBuild complete. Artifacts in $Dist"
Write-Host "  server  : $Dist\BARAQ\BARAQ.exe"
Write-Host "  agent   : $Dist\BARAQAgent.exe (+ fleet package)"
if (Test-Path (Join-Path $Dist "BARAQ-Installer.exe")) {
    Write-Host "  installer : $Dist\BARAQ-Installer.exe"
}