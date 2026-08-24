# BARAQ automated database backup - Windows scheduled task installer.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install_backup_task.ps1
#
# Registers a daily Windows scheduled task that runs:
#     venv\Scripts\python scripts\db_backup.py backup --encrypt --keep 14
#
# so the PostgreSQL database (pg_dump -Fc) is archived to backups\ every day
# with a SHA-256 manifest sidecar, AES-256-GCM encrypted under the DPAPI
# vault master key, and the newest 14 archives retained.
#
# Options:
#   -Time "03:00"     daily trigger time (default 03:00)
#   -Remove           delete the scheduled task instead of installing it
#
# Run from an elevated (Administrator) shell to create a task in the root
# task folder; without elevation the task is created for the current user
# only and still fires when that user is logged on.
param(
    [string]$Time = "03:00",
    [switch]$Remove
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$TaskName = "BARAQ-DB-Backup"
$Python = Join-Path $Root "venv\Scripts\python.exe"
$Script = Join-Path $Root "scripts\db_backup.py"

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Removed scheduled task: $TaskName"
    exit 0
}

if (-not (Test-Path $Python)) { throw "venv python not found at $Python - run start.bat first" }
if (-not (Test-Path $Script)) { throw "backup script not found at $Script" }

$action = New-ScheduledTaskAction -Execute $Python -Argument "`"$Script`" backup --encrypt --keep 14" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 2)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Description "BARAQ daily PostgreSQL backup (pg_dump -Fc, encrypted, keep 14)" | Out-Null

Write-Host "Installed scheduled task: $TaskName"
Write-Host "  schedule : daily at $Time"
Write-Host "  command  : $Python `"$Script`" backup --encrypt --keep 14"
Write-Host "  verify   : Get-ScheduledTaskInfo -TaskName $TaskName"
Write-Host "  test-run : $Python `"$Script`" backup --encrypt"