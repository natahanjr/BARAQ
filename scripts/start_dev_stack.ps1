# Start the full SentinelSOC dev stack (PostgreSQL + backend + Vite dashboard).
# Idempotent: each service is only started when its port is free.
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start_dev_stack.ps1
param(
    [switch]$Stop   # stop everything instead of starting
)

$ErrorActionPreference = "Stop"
$Root  = "F:\My Project\SentinelSOC"
$Logs  = "C:\Users\HAARAP~1\AppData\Local\Temp\opencode"
$PGPid = "$Logs\pg.pid"
$PY    = "$Root\venv\Scripts\python.exe"

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
    Stop-ServiceOn 5173 "vite"
    Stop-ServiceOn 8000 "backend"
    Stop-ServiceOn 55432 "postgres"
    return
}

Write-Host "[1/3] PostgreSQL :55432"
if (Test-Port 55432) {
    Write-Host "  already running"
} else {
    Start-Process -FilePath "C:\Users\Haaraphel\AppData\Local\Temp\opencode\pg\pgsql\bin\pg_ctl.exe" `
        -ArgumentList '-D', 'C:\Users\Haaraphel\AppData\Local\Temp\opencode\pg\data', `
        '-o', '-p 55432 -h 127.0.0.1', `
        '-l', "$Logs\pg.log" -WindowStyle Hidden | Out-Null
    Start-Sleep -Seconds 4
    Write-Host "  started (or already up)"
}

Write-Host "[2/3] Backend  :8000"
if (Test-Port 8000) {
    Write-Host "  already running"
} else {
    Start-Process -FilePath $PY -ArgumentList '-m', 'uvicorn', 'backend.main:app', `
        '--host', '127.0.0.1', '--port', '8000' -WorkingDirectory $Root -WindowStyle Hidden `
        -RedirectStandardOutput "$Logs\uvicorn-pg.out.log" -RedirectStandardError "$Logs\uvicorn-pg.err.log" | Out-Null
    Start-Sleep -Seconds 6
    Write-Host "  started"
}

Write-Host "[3/3] Vite     :5173"
if (Test-Port 5173) {
    Write-Host "  already running"
} else {
    Start-Process -FilePath "node" -ArgumentList 'node_modules\vite\bin\vite.js', `
        '--host', '127.0.0.1' -WorkingDirectory "$Root\frontend" -WindowStyle Hidden `
        -RedirectStandardOutput "$Logs\vite.out.log" -RedirectStandardError "$Logs\vite.err.log" | Out-Null
    Start-Sleep -Seconds 5
    Write-Host "  started"
}

Write-Host "`nDashboard: http://127.0.0.1:5173  (API on http://127.0.0.1:8000)"
