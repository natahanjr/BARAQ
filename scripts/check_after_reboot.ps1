# BARAQ - post-reboot verification helper.
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\check_after_reboot.ps1
# Prints whether the background task auto-started BARAQ after Windows reboot.
$Root = Split-Path -Parent $PSScriptRoot
$Logs = Join-Path $Root "logs"

Write-Host "== BARAQ post-reboot check =="
$task = Get-ScheduledTask -TaskName "BARAQ" -ErrorAction SilentlyContinue
if ($task) {
    $info = Get-ScheduledTaskInfo -TaskName "BARAQ"
    Write-Host ("Task    : {0} (last run {1}, result {2})" -f $task.State, $info.LastRunTime, $info.LastTaskResult)
} else {
    Write-Host "Task    : NOT registered"
}

$conn = Get-NetTCPConnection -LocalPort 8001 -State Listen -ErrorAction SilentlyContinue
if ($conn) { Write-Host "API     : LISTENING on 127.0.0.1:8001 (pid $($conn.OwningProcess))" }
else { Write-Host "API     : NOT listening on 8001" }

$pg = Get-CimInstance Win32_Process -Filter "Name='postgres.exe'" -ErrorAction SilentlyContinue
if ($pg) { Write-Host "Postgres: running (first pid $($pg[0].ProcessId))" }
else { Write-Host "Postgres: NOT running" }

$pidFile = Join-Path $Logs "server.pid"
if (Test-Path $pidFile) {
    $spid = (Get-Content $pidFile).Trim()
    $proc = Get-Process -Id $spid -ErrorAction SilentlyContinue
    if ($proc) { Write-Host "Wrapper : pid $spid running" } else { Write-Host "Wrapper : pid $spid NOT running (stale)" }
}

try {
    $r = Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/health" -TimeoutSec 10
    Write-Host "Health  : $($r.status) (instance held: $($r.single_instance.held))"
} catch {
    Write-Host "Health  : FAILED - $($_.Exception.Message)"
}

Write-Host "Log     : last 3 lines of logs\baraq.log:"
Get-Content (Join-Path $Logs "baraq.log") -Tail 3 -ErrorAction SilentlyContinue