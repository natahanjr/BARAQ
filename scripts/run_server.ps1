# SentinelSOC server wrapper - canonical entry point for the Windows service /
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

# --- environment defaults (do not override explicit values) ---
if (-not $env:SENTINEL_ENV)  { $env:SENTINEL_ENV = "production" }
$env:SENTINEL_SKIP_SECRET_GEN = "1"
$tls = $env:SENTINEL_TLS -in @("1", "true", "yes", "on")
if (-not $env:SENTINEL_PORT) { $env:SENTINEL_PORT = if ($tls) { "8443" } else { "8001" } }
$hostArg = if ($Lan) { "0.0.0.0" } else { "127.0.0.1" }

$python = Join-Path $Root "venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "venv not found at $python - run start.bat first" }

Set-Content -Path (Join-Path $Logs "server.pid") -Value $PID

$tlsArgs = @()
if ($tls) {
    $cert = Join-Path $Root "certs\sentinel.crt"
    $key  = Join-Path $Root "certs\sentinel.key"
    if (-not (Test-Path $cert) -or -not (Test-Path $key)) {
        throw "TLS enabled (SENTINEL_TLS) but $cert / $key missing - run scripts\gen_cert.ps1"
    }
    $tlsArgs = @("--ssl-certfile", $cert, "--ssl-keyfile", $key)
}

& $python -m uvicorn backend.main:app --host $hostArg --port $env:SENTINEL_PORT @tlsArgs