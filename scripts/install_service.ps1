# BARAQ - install / remove the backend as a Windows service.
#
# Prefers NSSM (auto-restart, log capture, proper service semantics). Falls
# back to a Task Scheduler "AtLogon" task (current user) when NSSM is
# unavailable. The DPAPI vault is CurrentUser-scoped, so the task runs as the
# logged-in user (not SYSTEM) or secrets cannot be decrypted. Both survive
# reboots; both run scripts\run_server.ps1 as the entry point.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 install [-Lan] [-UseTaskScheduler]
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 uninstall
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 status
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_service.ps1 fix
#
# Requires an elevated shell (this script re-launches itself elevated if not).
param(
    [ValidateSet("install", "uninstall", "status", "fix")]
    [string]$Action = "status",
    [string]$NssmPath = "",
    [switch]$UseTaskScheduler,
    [switch]$Lan
)
$ErrorActionPreference = "Stop"
$Root   = Split-Path -Parent $PSScriptRoot
$Wrapper = Join-Path $Root "scripts\run_server.ps1"
$Logs   = Join-Path $Root "logs"
New-Item -ItemType Directory -Path $Logs -Force | Out-Null

function Invoke-Elevated {
    if ((New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { return }
    Write-Host "Reloading with admin rights (UAC prompt)..."
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $Action" +
        $(if ($UseTaskScheduler) { " -UseTaskScheduler" }) + $(if ($Lan) { " -Lan" })
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

function Find-Nssm {
    if ($NssmPath -and (Test-Path $NssmPath)) { return $NssmPath }
    $c = Get-Command nssm -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($cand in @("C:\tools\nssm\nssm.exe", "C:\nssm\nssm.exe", "C:\Program Files\NSSM\nssm.exe")) {
        if (Test-Path $cand) { return $cand }
    }
    return ""
}

function Install-NssmService([string]$Nssm) {
    $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    & $Nssm install BARAQ $ps "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Wrapper | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "nssm install failed" }
    & $Nssm set BARAQ AppDirectory $Root | Out-Null
    & $Nssm set BARAQ AppStdout (Join-Path $Logs "nssm.out.log") | Out-Null
    & $Nssm set BARAQ AppStderr (Join-Path $Logs "nssm.err.log") | Out-Null
    & $Nssm set BARAQ AppExit Default Restart | Out-Null
    & $Nssm set BARAQ AppRestartDelay 5000 | Out-Null
    if ($Lan) {
        & $Nssm set BARAQ AppParameters "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Wrapper, "-Lan" | Out-Null
    }
    & $Nssm set BARAQ Start SERVICE_AUTO_START | Out-Null
    Write-Host "Service 'BARAQ' registered (NSSM, auto-start). Starting..."
    & $Nssm start BARAQ
    if ($LASTEXITCODE -eq 0) { Write-Host "  started." } else { Write-Host "  service registered but start returned exit $LASTEXITCODE" }
}

function Get-TaskSettings {
    # Batteries: a laptop on battery must NOT queue the task (DisallowStartIfOnBatteries
    # keeps it "Queued" forever). Restart on crash so the server self-heals.
    # NOTE: RestartInterval must be ISO 8601 ("PT1M"), not a TimeSpan - the
    # TimeSpan serializes to "00:01:00" which Task Scheduler rejects (0x80041318).
    $s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -StartWhenAvailable -RestartCount 3
    $s.RestartInterval = "PT1M"
    $s.StopIfGoingOnBatteries = $false
    return $s
}

function Install-Task {
    # Runs at LOGON as the CURRENT USER (no password prompt). The DPAPI vault
    # (secrets.dat) is CurrentUser-scoped, so a SYSTEM task could not decrypt
    # it; the logon task runs in your own session and secrets resolve normally.
    $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$Wrapper`""
    if ($Lan) { $args += " -Lan" }
    $action    = New-ScheduledTaskAction -Execute $ps -Argument $args -WorkingDirectory $Root
    $trigger   = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName "BARAQ" -Action $action -Trigger $trigger -Principal $principal -Settings (Get-TaskSettings) -Force | Out-Null
    Start-ScheduledTask -TaskName "BARAQ"
    Write-Host "Task 'BARAQ' registered (AtLogon, $env:USERDOMAIN\$env:USERNAME). Started now."
}

function Fix-Task {
    # Patch an existing "BARAQ" task: battery tolerance, start-if-missed, auto-restart.
    $task = Get-ScheduledTask -TaskName "BARAQ" -ErrorAction SilentlyContinue
    if (-not $task) { throw "Task 'BARAQ' is not registered - run install first." }
    $task.Settings.DisallowStartIfOnBatteries = $false
    $task.Settings.StopIfGoingOnBatteries     = $false
    $task.Settings.StartWhenAvailable         = $true
    $task.Settings.RestartCount               = 3
    $task.Settings.RestartInterval            = "PT1M"
    Set-ScheduledTask -TaskName "BARAQ" -Settings $task.Settings -ErrorAction Stop | Out-Null
    Write-Host "Task 'BARAQ' settings patched (battery-tolerant, auto-restart)."
}

function Remove-Service {
    $nssm = Find-Nssm
    if ($nssm -and ((& $nssm status BARAQ 2>$null) -ne $null)) {
        & $nssm stop BARAQ 2>$null | Out-Null
        & $nssm remove BARAQ confirm | Out-Null
        Write-Host "NSSM service 'BARAQ' removed."
        return
    }
    schtasks /Query /TN "BARAQ" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        schtasks /End /TN "BARAQ" 2>$null | Out-Null
        schtasks /Delete /TN "BARAQ" /F | Out-Null
        Write-Host "Task 'BARAQ' removed."
        return
    }
    Write-Host "No BARAQ service/task registered."
}

function Show-Status {
    $pidFile = Join-Path $Logs "server.pid"
    $pidVal = if (Test-Path $pidFile) { (Get-Content $pidFile).Trim() } else { "" }
    $svc = Get-Service -Name BARAQ -ErrorAction SilentlyContinue
    if ($svc) { Write-Host "Service : BARAQ - $($svc.Status)" }
    schtasks /Query /TN "BARAQ" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "Task    : BARAQ registered (AtLogon, $env:USERDOMAIN\$env:USERNAME)" }
    if ($pidVal) {
        $proc = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
        if ($proc) { Write-Host "Process : pid $pidVal running" } else { Write-Host "Process : pid $pidVal NOT running (stale pid file)" }
    } else {
        Write-Host "Process : no pid file (server never started via wrapper)"
    }
    $port = if ($env:BARAQ_TLS -in @("1","true","yes","on")) { 8443 } else { 8001 }
    $conn = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($conn) { Write-Host "Listening: 127.0.0.1:$port (pid $($conn.OwningProcess))" } else { Write-Host "Listening: NOT on $port" }
}

Invoke-Elevated
switch ($Action) {
    "install" {
        $nssm = ""
        if (-not $UseTaskScheduler) { $nssm = Find-Nssm }
        if ($nssm) { Install-NssmService $nssm } else { Install-Task }
    }
    "uninstall" { Remove-Service }
    "status"   { Show-Status }
    "fix"      { Fix-Task }
}