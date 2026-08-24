# Temporary helper: restart the BARAQ server (run elevated via UAC).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Root "logs"

# Rotate the giant error log (950MB of sklearn warning spam)
$errLog = Join-Path $Logs "server.err.log"
if (Test-Path $errLog) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    Move-Item -Path $errLog -Destination (Join-Path $Logs "server.err.log.$stamp.old") -Force
}

# Kill anything listening on port 8001
$conn = Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue
foreach ($c in $conn) {
    Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    Write-Output ("[KILL] stopped PID " + $c.OwningProcess)
}
Start-Sleep -Seconds 2

# Relaunch exactly like start.bat does
Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File scripts\run_server.ps1" `
    -WindowStyle Hidden `
    -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $Logs "server.out.log") `
    -RedirectStandardError (Join-Path $Logs "server.err.log")
Write-Output "[START] BARAQ relaunching on http://127.0.0.1:8001"
