# BARAQ - Windows Firewall rules for LAN SOC deployment.
# Run as Administrator.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_firewall.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_firewall.ps1 -Remove
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_firewall.ps1 -RemoteAddress 192.168.1.0/24
#
# Opens HTTPS (8443) for agents + analysts. Optionally HTTP (8001) for
# bootstrap. NEVER opens PostgreSQL (55432/5432) to the LAN.
param(
    [switch]$Remove,
    [switch]$AlsoHttp,
    [string]$RemoteAddress = ""   # e.g. 192.168.1.0/24 to restrict further
)
$ErrorActionPreference = "Stop"

function Test-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Host "Reloading elevated..." -ForegroundColor Yellow
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Remove) { $args += " -Remove" }
    if ($AlsoHttp) { $args += " -AlsoHttp" }
    if ($RemoteAddress) { $args += " -RemoteAddress $RemoteAddress" }
    Start-Process powershell -Verb RunAs -ArgumentList $args
    exit
}

$rules = @(
    @{ Name = "BARAQ SOC (HTTPS)"; Port = 8443 },
    @{ Name = "BARAQ SOC (HTTP)";  Port = 8001 }
)

if ($Remove) {
    foreach ($r in $rules) {
        $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -DisplayName $r.Name
            Write-Host "Removed: $($r.Name)" -ForegroundColor Green
        } else {
            Write-Host "Not present: $($r.Name)"
        }
    }
    exit 0
}

foreach ($r in $rules) {
    if ($r.Port -eq 8001 -and -not $AlsoHttp) { continue }

    $params = @{
        DisplayName = $r.Name
        Direction   = "Inbound"
        Protocol    = "TCP"
        LocalPort   = $r.Port
        Action      = "Allow"
        Profile     = "Domain,Private"
        Enabled     = "True"
        ErrorAction = "SilentlyContinue"
    }
    if ($RemoteAddress) {
        $params["RemoteAddress"] = $RemoteAddress
    }

    $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Already exists: $($r.Name) (port $($r.Port))" -ForegroundColor Cyan
    } else {
        New-NetFirewallRule @params | Out-Null
        Write-Host "Created: $($r.Name) (port $($r.Port))" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Active BARAQ firewall rules:" -ForegroundColor Yellow
Get-NetFirewallRule -DisplayName "BARAQ*" -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Enabled, Direction, Action |
    Format-Table -AutoSize

Write-Host "PostgreSQL (55432) is intentionally NOT opened to the LAN." -ForegroundColor DarkGray
