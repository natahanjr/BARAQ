# BARAQ installer packaging (Inno Setup).
#
# Stages the built server (dist\BARAQ folder build) + operational
# scripts, then compiles deploy\installer\baraq.iss with ISCC. When Inno
# Setup is missing it is installed silently via winget (freeware), or a clear
# message points to the .iss so it can be compiled manually on a build host.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build_installer.ps1
param(
    [string]$Version = "1.0.0"
)
$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $PSScriptRoot
$Dist   = Join-Path $Root "dist"
$Staging = Join-Path $Root "deploy\installer\staging"
$IssFile = Join-Path $Root "deploy\installer\baraq.iss"

if (-not (Test-Path (Join-Path $Dist "BARAQ\BARAQ.exe"))) {
    throw "dist\BARAQ\BARAQ.exe missing - build the server first (build_release.ps1)."
}

function Find-Iscc {
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        "$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
        "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
    )) { if (Test-Path $p) { return $p } }
    return ""
}

function Install-Inno {
    Write-Host "  installing Inno Setup via winget (first run only)..."
    & winget install --id JRSoftware.InnoSetup -e --accept-source-agreements --accept-package-agreements --disable-interactivity | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "winget install of Inno Setup failed" }
    Start-Sleep -Seconds 5
}

# ------------------------------------------------------------ staging
Write-Host "== staging installer payload =="
if (Test-Path $Staging) { Remove-Item $Staging -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $Staging "server") -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $Staging "scripts") -Force | Out-Null

# Flat server payload: copy the CONTENTS of dist\BARAQ so the exe lands at
# {app}\BARAQ.exe (the .iss [Icons]/[Run] entries expect the exe at the app
# root, not in a nested folder).
Copy-Item (Join-Path $Dist "BARAQ\*") (Join-Path $Staging "server") -Recurse -Force

# Bundle the portable PostgreSQL binaries if present (dist\pg) so the
# installed product is fully offline-capable; the [Run] download step stays
# as a fallback for standalone script use.
$bundledPg = Join-Path $Dist "pg"
if (Test-Path (Join-Path $bundledPg "bin\pg_ctl.exe")) {
    Write-Host "  bundling portable PostgreSQL (dist\pg) into the payload ..."
    Copy-Item $bundledPg (Join-Path $Staging "server\pg") -Recurse -Force
} else {
    Write-Host "  [warn] dist\pg not found - installer will rely on the on-demand PostgreSQL download task."
}

foreach ($script in @(
    "pg_setup.ps1", "download_postgres.ps1", "provision_postgres.ps1",
    "install_service.ps1", "run_server.ps1", "run_server.py",
    "start_pg.cmd", "start_pg_server.cmd", "gen_cert.ps1", "db_backup.py", "agent.py"
)) {
    Copy-Item (Join-Path $Root "scripts\$script") (Join-Path $Staging "scripts") -Force
}
Copy-Item (Join-Path $Root "alembic.ini") (Join-Path $Staging "scripts") -Force

# ------------------------------------------------------------ compile
$iscc = Find-Iscc
if (-not $iscc) {
    Write-Host "  Inno Setup not found."
    try { Install-Inno } catch {
        Write-Host "  [FAIL] $($_.Exception.Message)"
        Write-Host "  Compile manually on a build host: iscc `"$IssFile`" (payload already staged at $Staging)"
        exit 1
    }
    $iscc = Find-Iscc
}

Write-Host "  compiling $IssFile (version $Version) ..."
& $iscc /DAppVersion=$Version /O$Dist $IssFile
if ($LASTEXITCODE -ne 0) { throw "ISCC compile failed" }
Write-Host "  installer: $Dist\BARAQ-Setup-$Version.exe"
Remove-Item $Staging -Recurse -Force -ErrorAction SilentlyContinue