# BARAQ PostgreSQL portable cluster manager.
#
# Single source of truth for the local/embedded PostgreSQL cluster. Works on
# ANY machine with no hard-coded paths: everything is derived from the script
# location, environment variables and machine defaults. No admin rights are
# needed (the cluster runs under pg_ctl, not as a service).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action ensure
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action start
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action stop
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action status
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\pg_setup.ps1 -Action init
#
# Actions:
#   ensure  - init the cluster if missing, then start it if not running (default)
#   init    - create the data directory if missing (never touches an existing one)
#   start   - start the cluster if it is not already listening
#   stop    - stop the cluster (pg_ctl fast shutdown)
#   status  - report where the cluster lives and whether it is up
#
# Locations (first match wins):
#   * binaries : $env:BARAQ_PG_BIN  > <project>\pg\bin  > <home>\bin
#                > "$env:ProgramFiles\PostgreSQL\*\bin"    > PATH
#   * data dir : $env:BARAQ_PG_HOME (full path to the PG home) otherwise
#                "$env:LOCALAPPDATA\BARAQ\postgres" (per-user, stable)
#   * bind     : 127.0.0.1, port $env:BARAQ_PG_PORT (default 55432)
#   * auth     : trust, localhost-only - the cluster never listens remotely
param(
    [ValidateSet("ensure", "init", "start", "stop", "status")]
    [string]$Action = "ensure",
    [string]$PgHome = ""
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

# ------------------------------------------------------------------ defaults
$Port = if ($env:BARAQ_PG_PORT) { $env:BARAQ_PG_PORT } else { "5432" }
$Bind = if ($env:BARAQ_PG_HOST) { $env:BARAQ_PG_HOST } else { "127.0.0.1" }
if (-not $PgHome) { $PgHome = $env:BARAQ_PG_HOME }
if (-not $PgHome) { $PgHome = Join-Path $env:LOCALAPPDATA "BARAQ\postgres" }
$PgHome = [System.IO.Path]::GetFullPath($PgHome)
$Data = Join-Path $PgHome "data"
$Log  = Join-Path $PgHome "pg.log"

# ------------------------------------------------------------ binary lookup
function Get-PgBin([string]$Tool) {
    $candidates = @()
    if ($env:BARAQ_PG_BIN) {
        $candidates += Join-Path $env:BARAQ_PG_BIN "$Tool.exe"
        $candidates += Join-Path $env:BARAQ_PG_BIN "bin\$Tool.exe"
    }
    $candidates += Join-Path $Root "pg\bin\$Tool.exe"
    $candidates += Join-Path $PgHome "bin\$Tool.exe"
    foreach ($pg in @(Get-ChildItem (Join-Path $env:ProgramFiles "PostgreSQL") -Directory -ErrorAction SilentlyContinue)) {
        $candidates += Join-Path $pg.FullName "bin\$Tool.exe"
    }
    foreach ($cand in $candidates) {
        if ($cand -and (Test-Path $cand)) { return $cand }
    }
    $fromPath = Get-Command "$Tool.exe" -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    return ""
}

function Assert-PgTools {
    foreach ($tool in @("pg_ctl", "initdb")) {
        if (-not (Get-PgBin $tool)) {
            throw "PostgreSQL tools not found. Run scripts\download_postgres.ps1 (bundles PG into <project>\pg) or set BARAQ_PG_BIN, or install PostgreSQL 16+."
        }
    }
}

# ---------------------------------------------------------------- actions
function Test-ClusterUp {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

# True only when the cluster ACCEPTS queries. After an unclean shutdown the
# port may listen while crash recovery is still replaying WAL ("the database
# system is starting up") - connecting then would fail, so callers must gate
# on this, not on Test-ClusterUp alone.
function Test-PgReady {
    $isready = Get-PgBin "pg_isready"
    if (-not $isready) { return (Test-ClusterUp) }
    & $isready -h $Bind -p $Port -t 2 -q | Out-Null
    return ($LASTEXITCODE -eq 0)
}

function Invoke-Init {
    Assert-PgTools
    New-Item -ItemType Directory -Path $PgHome -Force | Out-Null
    if (Test-Path (Join-Path $Data "PG_VERSION")) {
        Write-Host "  cluster already exists at $Data"
        return
    }
    $initdb = Get-PgBin "initdb"
    Write-Host "  initialising cluster at $Data ..."
    & $initdb -D $Data -U postgres -A trust -E UTF8 --locale=C | Select-Object -Last 3
    if ($LASTEXITCODE -ne 0) { throw "initdb failed - see output above" }
    $conf = Join-Path $Data "postgresql.conf"
    if (Test-Path $conf) {
        $text = Get-Content $conf -Raw
        $lines = @(
            "listen_addresses = '127.0.0.1'",
            "port = $Port",
            "max_connections = 50",
            "shared_buffers = 64MB",
            "logging_collector = off"
        )
        Add-Content -Path $conf -Value "`n# --------------------------------------------------------`n# BARAQ portable cluster settings`n# --------------------------------------------------------`n$($lines -join "`n")"
    }
    Write-Host "  cluster initialised (superuser: postgres, trust auth, localhost only)."
}

function Invoke-Start {
    Assert-PgTools
    Invoke-Init
    if ((Test-ClusterUp) -and (Test-PgReady)) {
        Write-Host "  cluster already running on $Bind`:$Port"
        return
    }
    if (-not (Test-ClusterUp)) {
        $pgctl = Get-PgBin "pg_ctl"
        # -t 600: after an unclean shutdown the cluster may spend several
        # minutes fsync-ing / replaying WAL before it accepts connections.
        & $pgctl -D $Data -o "-p $Port -h $Bind" -l $Log start -w -t 600
    }
    # Wait until queries are accepted - listening alone is not enough when the
    # cluster is mid-recovery after an unclean shutdown.
    $deadline = [DateTime]::UtcNow.AddSeconds(660)
    while (-not (Test-PgReady) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
        if (Test-Path $Log) {
            $fatal = Get-Content $Log -Tail 15 | Where-Object { $_ -match "FATAL|aborting startup" }
            if ($fatal -and -not (Get-Process postgres -ErrorAction SilentlyContinue)) { break }
        }
    }
    if (-not (Test-PgReady)) {
        $tail = if (Test-Path $Log) { (Get-Content $Log -Tail 12) -join "`n" } else { "no log" }
        throw "cluster not ready on $Bind`:$Port (see $Log)`n$tail"
    }
    if (-not (Test-ClusterUp)) {
        throw "cluster did not come up on $Bind`:$Port (see $Log)"
    }
    Write-Host "  cluster started on $Bind`:$Port (data: $Data)"
}

function Invoke-Stop {
    if (-not (Test-ClusterUp)) { Write-Host "  cluster not running"; return }
    $pgctl = Get-PgBin "pg_ctl"
    & $pgctl -D $Data stop -m fast -w -t 30 | Out-Null
    Write-Host "  cluster stopped"
}

function Show-Status {
    $pgctl = Get-PgBin "pg_ctl"
    Write-Host "binaries : $(if ($pgctl) { Split-Path $pgctl -Parent } else { 'NOT FOUND (run scripts\download_postgres.ps1)' })"
    Write-Host "data dir : $Data"
    Write-Host "endpoint : $Bind`:$Port  listening: $(Test-ClusterUp)"
}

# ------------------------------------------------------------------- main
Write-Host "== BARAQ PostgreSQL ($Action) =="
switch ($Action) {
    "ensure"   { Invoke-Start }
    "init"     { Invoke-Init }
    "start"    { Invoke-Start }
    "stop"     { Invoke-Stop }
    "status"   { Show-Status }
}
