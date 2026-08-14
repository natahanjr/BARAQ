# BARAQ - grant / verify the privileges the collectors need.
#
# The event-log collectors read the Security channel and the PowerShell /
# Sysmon operational channels. A non-elevated process can read Security only
# when its user is a member of the built-in "Event Log Readers" group (or
# when the collector runs elevated). This script:
#
#   check  -> report which channels the current user can read today
#   grant  -> add the current user to "Event Log Readers" + enable the
#             channels BARAQ watches (requires elevation; self-elevates)
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\elevate_permissions.ps1 check
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\elevate_permissions.ps1 grant
#
# Exit code 0 = every channel readable (grant made no changes needed).
# Exit code 1 = at least one channel is still not readable.
param(
    [ValidateSet("check", "grant")]
    [string]$Action = "check",
    [string[]]$Channel = @(
        "Security",
        "System",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational"
    )
)
$ErrorActionPreference = "Stop"
$LogReadersGroup = "Event Log Readers"

function Test-IsElevated {
    return (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ChannelStatus([string]$name) {
    try {
        $out = & wevtutil gl $name 2>$null
        if ($LASTEXITCODE -ne 0) { return @{ name = $name; ok = $false; reason = "channel not found / not enabled" } }
        $enabled = ($out | Select-String -Pattern "enabled:\s*true" -Quiet)
        return @{ name = $name; ok = [bool]$enabled; reason = if ($enabled) { "ok" } else { "channel disabled" } }
    } catch {
        return @{ name = $name; ok = $false; reason = $_.Exception.Message }
    }
}

function Test-ReadAccess([string]$name) {
    # Real read probe: open the channel for backward read. (1314) means the
    # caller lacks the SeSecurityPrivilege / membership needed for Security.
    try {
        $sig = @"
using System;
using System.Runtime.InteropServices;
public static class EvtProbe {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr OpenEventLog(string server, string source);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool CloseEventLog(IntPtr h);
}
"@
        if (-not ("EvtProbe" -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction Stop }
        $h = [EvtProbe]::OpenEventLog($null, $name)
        if ($h -eq [IntPtr]::Zero) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return @{ name = $name; ok = $false; error = $err }
        }
        [void][EvtProbe]::CloseEventLog($h)
        return @{ name = $name; ok = $true; error = 0 }
    } catch {
        return @{ name = $name; ok = $false; error = -1 }
    }
}

function Invoke-Grant {
    if (-not (Test-IsElevated)) {
        Write-Host "Reloading with admin rights (UAC prompt)..."
        $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" grant"
        Start-Process powershell -Verb RunAs -ArgumentList $args
        exit
    }
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $already = (& net localgroup $LogReadersGroup 2>$null | Select-String -Pattern "^$([regex]::Escape($me))$" -Quiet)
    if ($already) {
        Write-Host "[ok] $me is already a member of $LogReadersGroup"
    } else {
        & net localgroup $LogReadersGroup $me /add | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Failed to add $me to $LogReadersGroup (exit $LASTEXITCODE)" }
        Write-Host "[ok] Added $me to $LogReadersGroup (new logins pick it up; existing sessions may need a sign-out/in)"
    }
    foreach ($ch in $Channel) {
        if ($ch -eq "Microsoft-Windows-Sysmon/Operational" -and -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-Sysmon")) {
            Write-Host "[skip] $ch - Sysmon is not installed on this host"
            continue
        }
        & wevtutil sl $ch /e:true | Out-Null
        Write-Host "[ok] $ch enabled"
    }
}

function Invoke-Check {
    $fail = 0
    foreach ($ch in $Channel) {
        $status = Get-ChannelStatus $ch
        if (-not $status.ok) {
            Write-Host ("[--] {0}: {1}" -f $ch, $status.reason)
            continue
        }
        $probe = Test-ReadAccess $ch
        if ($probe.ok) {
            Write-Host "[ok] $ch - readable"
        } else {
            $fail++
            $hint = if ($probe.error -eq 1314) {
                "requires SeSecurityPrivilege: run 'grant' or add this user to the '$LogReadersGroup' group"
            } else {
                "read failed (win32 error $($probe.error))"
            }
            Write-Host "[!!] $ch - $hint"
        }
    }
    if ($fail -gt 0) {
        Write-Host ""
        Write-Host "Fix:  powershell -NoProfile -ExecutionPolicy Bypass -File scripts\elevate_permissions.ps1 grant"
        exit 1
    }
    Write-Host ""
    Write-Host "All watched channels are readable."
}

switch ($Action) {
    "grant" { Invoke-Grant }
    "check" { Invoke-Check }
}