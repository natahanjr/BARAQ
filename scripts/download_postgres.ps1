# Download the portable PostgreSQL binaries bundle for BARAQ.
#
# Fetches the official EnterpriseDB "binaries only" package (no installer, no
# admin rights) and lays it out so scripts\pg_setup.ps1 finds it in the
# project-local <project>\pg\bin folder. After this runs once, the product is
# fully self-contained on this machine.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\download_postgres.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\download_postgres.ps1 -Version 17.3
#
# Variables:
#   -Version    PG version to fetch (default 16.8; URL pattern tries
#               "<version>-1" variants automatically)
#   -Target     extraction root (default <project>\pg; bin ends up in pg\bin)
param(
    [string]$Version = "16.8",
    [string]$Target = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Target) { $Target = Join-Path $Root "pg" }
$Target = [System.IO.Path]::GetFullPath($Target)
$BinDir = Join-Path $Target "bin"

if (Test-Path (Join-Path $BinDir "pg_ctl.exe")) {
    Write-Host "PostgreSQL binaries already present at $BinDir - nothing to do."
    exit 0
}

$work = Join-Path $env:TEMP "baraq_pg_download"
New-Item -ItemType Directory -Path $work -Force | Out-Null
$zip  = Join-Path $work "postgresql-$Version-windows-x64-binaries.zip"
$url  = "https://get.enterprisedb.com/postgresql/postgresql-$Version-windows-x64-binaries.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
function Test-ValidZip([string]$Path) {
    if (-not (Test-Path $Path)) { return $false }
    try {
        $a = [System.IO.Compression.ZipFile]::OpenRead($Path)
        $n = $a.Entries.Count
        $a.Dispose()
        return $n -gt 0
    } catch { return $false }
}
if (-not (Test-ValidZip $zip)) {
    $ok = $false
    foreach ($candidate in @(
        "postgresql-$Version-windows-x64-binaries.zip",
        "postgresql-$Version-1-windows-x64-binaries.zip"
    )) {
        $u = "https://get.enterprisedb.com/postgresql/$candidate"
        Write-Host "  trying $u ..."
        curl.exe -sL -fail --retry 3 --retry-all-errors --retry-delay 5 -C - -o $zip --max-time 3600 $u
        if ($LASTEXITCODE -eq 0 -and (Test-ValidZip $zip)) { $ok = $true; break }
        Write-Host "  download incomplete or corrupt - retrying next mirror..."
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }
    if (-not $ok) {
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
        throw "Could not download a valid PostgreSQL $Version archive. Fix the version (e.g. -Version 16.8) or install PostgreSQL manually and set BARAQ_PG_BIN."
    }
    Write-Host "  downloaded $([math]::Round((Get-Item $zip).Length / 1MB)) MB (integrity verified)"
}

Write-Host "  extracting to $Target ..."
New-Item -ItemType Directory -Path $Target -Force | Out-Null
try {
    Expand-Archive -Path $zip -DestinationPath $Target -Force
} catch {
    throw "Extraction failed: $($_.Exception.Message)"
}

$nested = Get-ChildItem $Target -Directory | Where-Object { $_.Name -like "pgsql*" } | Select-Object -First 1
if ($nested -and (Test-Path (Join-Path $nested.FullName "bin\pg_ctl.exe"))) {
    $srcBin = Join-Path $nested.FullName "bin"
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
    Get-ChildItem $srcBin -File | Move-Item -Destination $BinDir -Force
    Remove-Item $nested.FullName -Recurse -Force
} elseif (-not (Test-Path (Join-Path $BinDir "pg_ctl.exe"))) {
    throw "Extraction did not produce $BinDir\pg_ctl.exe - unexpected package layout."
}

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Write-Host "Portable PostgreSQL $Version ready at $BinDir"
Write-Host "Next: powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action ensure"