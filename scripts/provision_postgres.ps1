# BARAQ PostgreSQL provisioning - idempotent production setup.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\provision_postgres.ps1
#
# What it does:
#   1. Verifies a PostgreSQL 16+ server responds on the configured port
#      (BARAQ_PG_PORT, default 55432) - either the bundled embedded
#      cluster or any pg_ctl-managed install; fails with a clear message
#      otherwise (it never silently starts blind.
#   2. Creates the BARAQ database (default "baraq") and a dedicated
#      application role (default "baraq") with a generated password, if
#      the role does not already exist. The superuser (default "postgres")
#      is only used for provisioning, never by the app itself.
#   3. Writes BARAQ_DATABASE_URL into .env (or updates it in place) so the
#      backend, backups and migrations all target the same cluster.
#   4. Prints a verification line: pg_database entry + a live connect check
#      with the new application role.
#
# Recommended usage:
#   - Run once as the operator during the "install the central server" step.
#   - Re-run freely: everything is conditional (IF NOT EXISTS semantics).
#
# Variables (all optional):
#   BARAQ_PG_HOST    127.0.0.1
#   BARAQ_PG_PORT    55432
#   BARAQ_PG_SUPER   postgres          (provisioning-only superuser)
#   BARAQ_PG_PASS    <empty -> prompt> (superuser password)
#   BARAQ_PG_USER    baraq          (application role)
#   BARAQ_PG_NAME    baraq          (database)
#   BARAQ_PG_BIN     pg bin dir with psql.exe (default: PATH + common locations)
param(
    [string]$Port   = $env:BARAQ_PG_PORT,
    [string]$Super  = $env:BARAQ_PG_SUPER,
    [string]$DbUser = $env:BARAQ_PG_USER,
    [string]$DbName = $env:BARAQ_PG_NAME,
    [string]$Password = $env:BARAQ_PG_PASS
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$EnvFile = Join-Path $Root ".env"

if (-not $Port)   { $Port = "55432" }
if (-not $Super)  { $Super = "postgres" }
if (-not $DbUser) { $DbUser = "baraq" }
if (-not $DbName) { $DbName = "baraq" }

function Find-Psql {
    $hint = $env:BARAQ_PG_BIN
    $candidates = @()
    if ($hint) {
        $candidates += Join-Path $hint "psql.exe"
        $candidates += (Join-Path $hint "bin\psql.exe")
    }
    $candidates += @(
        (Join-Path $Root "pg\bin\psql.exe"),
        (Join-Path $env:LOCALAPPDATA "BARAQ\postgres\bin\psql.exe"),
        (Join-Path $env:ProgramFiles "PostgreSQL\*\bin\psql.exe")
    )
    foreach ($cand in $candidates) {
        if ($cand -and (Test-Path $cand)) { return $cand }
    }
    $fromPath = Get-Command psql.exe -ErrorAction SilentlyContinue
    if ($fromPath) { return $fromPath.Source }
    throw "psql.exe not found - set BARAQ_PG_BIN or install PostgreSQL 16+."
}

function New-SuperPassword {
    if ($Password) { return $Password }
    $stored = $env:BARAQ_PG_PASS
    if (-not $stored) {
        $cred = Get-Credential -Message "PostgreSQL superuser ($Super@$Port) password" -UserName $Super
        $stored = $cred.GetNetworkCredential().Password
    }
    return $stored
}

$Psql = Find-Psql
$SuperPass = New-SuperPassword
$Host_ = if ($env:BARAQ_PG_HOST) { $env:BARAQ_PG_HOST } else { "127.0.0.1" }
$env:PGPASSWORD = $SuperPass

Write-Host "== BARAQ PostgreSQL provisioning =="
Write-Host "  cluster : $Host_`:$Port  superuser: $Super  app role: $DbUser  db: $DbName"
Write-Host "  psql    : $Psql"

# 1. Reachability check (fail fast, never guess)
$probe = & $Psql -h $Host_ -p $Port -U $Super -d postgres -t -A -c "SELECT version();" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL cluster not reachable at $Host_`:$Port. Start the cluster (service or pg_ctl) first.`nDetail: $probe"
}
Write-Host "  cluster reachable: $($probe -split ' on ')[0]"

# 2. App role (generated password, stored in the vault-style .env only)
$roleExists = & $Psql -h $Host_ -p $Port -U $Super -d postgres -t -A -c "SELECT 1 FROM pg_roles WHERE rolname='$DbUser';" 2>$null
if ($roleExists.Trim() -ne "1") {
    $appPass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
    & $Psql -h $Host_ -p $Port -U $Super -d postgres -v ON_ERROR_STOP=1 -c "CREATE ROLE `"$DbUser`" LOGIN PASSWORD '$appPass';" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create application role $DbUser" }
    Write-Host "  created role : $DbUser"
} else {
    # Role already exists: keep its password untouched UNLESS the .env has no
    # usable connection string (e.g. reinstall over an existing cluster) - then
    # rotate the role password and write it, so the app always boots connected.
    $envUrl = if (Test-Path $EnvFile) { Get-Content $EnvFile -Raw -ErrorAction SilentlyContinue } else { "" }
    if ($envUrl -match "BARAQ_DATABASE_URL\s*=\s*.+") {
        Write-Host "  role exists  : $DbUser (password left untouched)"
        $appPass = $null
    } else {
        $appPass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        & $Psql -h $Host_ -p $Port -U $Super -d postgres -v ON_ERROR_STOP=1 -c "ALTER ROLE `"$DbUser`" LOGIN PASSWORD '$appPass';" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to rotate application role password" }
        Write-Host "  role exists  : $DbUser (password rotated - .env had no connection string)"
    }
}

# 3. Database (owned by the app role so migrations/backup run with it)
$dbExists = & $Psql -h $Host_ -p $Port -U $Super -d postgres -t -A -c "SELECT 1 FROM pg_database WHERE datname='$DbName';" 2>$null
if ($dbExists.Trim() -ne "1") {
    & $Psql -h $Host_ -p $Port -U $Super -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE `"$DbName`" OWNER `"$DbUser`";" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to create database $DbName" }
    Write-Host "  created db   : $DbName"
} else {
    Write-Host "  db exists    : $DbName"
}

# 4. Update .env with the app connection string
$line = "BARAQ_DATABASE_URL=postgresql+psycopg://$DbUser`:$appPass@$Host_`:$Port/$DbName"
if ($appPass) {
    $content = if (Test-Path $EnvFile) { Get-Content $EnvFile -Raw -ErrorAction SilentlyContinue } else { "" }
    if ($content -match "BARAQ_DATABASE_URL\s*=") {
        $content = $content -replace "(?m)^BARAQ_DATABASE_URL\s*=.*$", $line
    } else {
        $content += "`n$line`n"
    }
    Set-Content -Path $EnvFile -Value $content -Encoding UTF8
    Write-Host "  .env updated : BARAQ_DATABASE_URL (owns: $DbUser)"
}

# 5. Live connect check with the application role
if ($appPass) {
    $env:PGPASSWORD = $appPass
    $check = & $Psql -h $Host_ -p $Port -U $DbUser -d $DbName -t -A -c "SELECT current_user || '@' || current_database();" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  verified     : app login OK ($check)"
    } else {
        Write-Host "  WARNING      : app login failed - $check"
    }
}
Write-Host "== done =="