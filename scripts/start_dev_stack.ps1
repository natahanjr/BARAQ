# Start the full BARAQ dev stack (PostgreSQL + backend + Vite dashboard).
# Idempotent: each service is only started when its port is free.
# Machine-independent: every path is derived from this script's location.
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start_dev_stack.ps1
param(
    [switch]$Stop   # stop everything instead of starting
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Root "logs"
New-Item -ItemType Directory -Path $Logs -Force | Out-Null
$PGSetup = Join-Path $PSScriptRoot "pg_setup.ps1"
$PY    = Join-Path $Root "venv\Scripts\python.exe"

function Test-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

function Stop-ServiceOn([int]$Port, [string]$Name) {
    Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        ForEach-Object {
            Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "  stopped $Name (pid $($_.OwningProcess))"
        }
}

if ($Stop) {
    Write-Host "[stop] tearing down dev stack"
    & powershell -NoProfile -ExecutionPolicy Bypass -File $PGSetup -Action stop
    Stop-ServiceOn 5173 "vite"
    Stop-ServiceOn 8001 "backend"
    return
}

Write-Host "[1/3] PostgreSQL"
& powershell -NoProfile -ExecutionPolicy Bypass -File $PGSetup -Action ensure

Write-Host "[2/3] Backend  :8001"
if (Test-Port 8001) {
    Write-Host "  already running"
} else {
    Start-Process -FilePath $PY -ArgumentList '-m', 'uvicorn', 'backend.main:app', `
        '--host', '127.0.0.1', '--port', '8001' -WorkingDirectory $Root -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Logs "uvicorn-pg.out.log") `
        -RedirectStandardError (Join-Path $Logs "uvicorn-pg.err.log") | Out-Null
    Start-Sleep -Seconds 6
    Write-Host "  started"
}

Write-Host "[3/3] Vite     :5173"
if (Test-Port 5173) {
    Write-Host "  already running"
} else {
    Start-Process -FilePath "node" -ArgumentList 'node_modules\vite\bin\vite.js', `
        '--host', '127.0.0.1' -WorkingDirectory (Join-Path $Root "frontend") -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $Logs "vite.out.log") `
        -RedirectStandardError (Join-Path $Logs "vite.err.log") | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "  started"
}

Write-Host "`nDashboard: http://127.0.0.1:5173  (API on http://127.0.0.1:8001)"