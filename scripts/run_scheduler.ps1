# BARAQ - standalone scheduler service (roadmap 3.1).
#
# Runs the collection + detection loop as its own process so the API can
# scale horizontally (BARAQ_ROLE=api). The scheduler holds the distributed
# lock (Redis if BARAQ_REDIS_URL is set, else Postgres advisory), so exactly
# one scheduler is active per deployment.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_scheduler.ps1
param(
    [int]$Interval = 15
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path "$Root\venv\Scripts\python.exe")) {
    Write-Host "venv not found at $Root\venv - create it with: python -m venv venv" -ForegroundColor Red
    exit 1
}

$env:PYTHONPATH = $Root
& "$Root\venv\Scripts\python.exe" -m backend.scheduler_service --interval $Interval
exit $LASTEXITCODE