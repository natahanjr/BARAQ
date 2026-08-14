# BARAQ server wrapper - canonical entry point for the Windows service /
# scheduled task / manual background start.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_server.ps1 [-Lan]
#
# Sets sane defaults (production profile, port 8001 or 8443 under TLS) and runs
# the backend in the foreground so the service manager can monitor it. A PID
# file is written to logs\server.pid for status checks.
param(
    [switch]$Lan   # listen on 0.0.0.0 instead of 127.0.0.1
)
$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $PSScriptRoot
$Logs   = Join-Path $Root "logs"
New-Item -ItemType Directory -Path $Logs -Force | Out-Null

# --- ensure the local PostgreSQL cluster is up (service/task entry point
#     must not depend on start.bat having run first) ---
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Root "scripts\pg_setup.ps1") -Action ensure
if ($LASTEXITCODE -ne 0) {
    throw "PostgreSQL could not be started - see scripts\pg_setup.ps1"
}

# --- environment defaults (do not override explicit values) ---
# Mirror backend/config.py: default "development" (plain HTTP on 127.0.0.1,
# same as start.bat). Set BARAQ_ENV=production explicitly for hardened runs.
if (-not $env:BARAQ_ENV)  { $env:BARAQ_ENV = "development" }
$env:BARAQ_SKIP_SECRET_GEN = "1"
$tls = $env:BARAQ_TLS -in @("1", "true", "yes", "on")
if (-not $env:BARAQ_PORT) { $env:BARAQ_PORT = if ($tls) { "8443" } else { "8001" } }
$hostArg = if ($Lan) { "0.0.0.0" } else { "127.0.0.1" }

$packaged = Join-Path $Root "BARAQ.exe"
$python   = Join-Path $Root "venv\Scripts\python.exe"
if (Test-Path $packaged) {
    # Installed (PyInstaller) layout: run the frozen server executable.
    Set-Content -Path (Join-Path $Logs "server.pid") -Value $PID
    & $packaged
    exit $LASTEXITCODE
}
if (-not (Test-Path $python)) { throw "venv not found at $python - run start.bat first" }

Set-Content -Path (Join-Path $Logs "server.pid") -Value $PID

$tlsArgs = @()
if ($tls) {
    $cert = Join-Path $Root "certs\baraq.crt"
    $key  = Join-Path $Root "certs\baraq.key"
    if (-not (Test-Path $cert) -or -not (Test-Path $key)) {
        throw "TLS enabled (BARAQ_TLS) but $cert / $key missing - run scripts\gen_cert.ps1"
    }
    $tlsArgs = @("--ssl-certfile", $cert, "--ssl-keyfile", $key)
}

& $python -m uvicorn backend.main:app --host $hostArg --port $env:BARAQ_PORT @tlsArgs