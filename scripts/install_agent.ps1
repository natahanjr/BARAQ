<#
.SYNOPSIS
    BARAQ Agent - One-Click Installer for Windows Endpoints.

.DESCRIPTION
    Installs the BARAQ telemetry agent on a Windows laptop/PC.
    The agent collects Windows Event Logs, process activity, and network
    connections, then sends them to the central BARAQ server.

    This script is designed for non-technical users (library staff,
    finance team, registrar, etc.) to install with a single command.

.PARAMETER Server
    The BARAQ server URL (e.g., http://192.168.1.100:8001).

.PARAMETER Key
    The agent API key for authentication.

.PARAMETER Org
    Department/organization name (e.g., "library", "finance").

.PARAMETER Interval
    Collection interval in seconds (default: 15).

.EXAMPLE
    # One-liner from network share:
    powershell -ExecutionPolicy Bypass -File \\server\share\install_agent.ps1 -Server http://192.168.1.100:8001 -Key baraq-lib-01 -Org library

    # One-liner from internet:
    irm https://your-server:8001/scripts/install_agent.ps1 | iex -Args --Server http://your-server:8001 --Key baraq-lib-01 --Org library
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [string]$Key,

    [Parameter(Mandatory=$false)]
    [string]$Org = "default",

    [Parameter(Mandatory=$false)]
    [int]$Interval = 15,

    [Parameter(Mandatory=$false)]
    [string]$AgentDir = "$env:LOCALAPPDATA\BARAQAgent",

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "BARAQ Agent"
$AgentScript = "$AgentDir\agent.py"
$ConfigFile = "$AgentDir\agent.config.json"
$LogFile = "$AgentDir\agent.log"

# ── Colors ────────────────────────────────────────────────────────────────
function Write-Status($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)      { Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)     { Write-Host "[ERROR] $msg" -ForegroundColor Red }

# ── Banner ────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   BARAQ Agent Installer v2.0" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Uninstall ─────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Status "Uninstalling BARAQ Agent..."

    # Remove scheduled task
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-OK "Scheduled task removed"
    } catch {
        Write-Warn "Scheduled task not found (already removed?)"
    }

    # Remove agent files
    if (Test-Path $AgentDir) {
        Remove-Item -Path $AgentDir -Recurse -Force
        Write-OK "Agent files removed from $AgentDir"
    }

    Write-Host ""
    Write-OK "BARAQ Agent uninstalled successfully."
    Write-Host ""
    exit 0
}

# ── Check prerequisites ──────────────────────────────────────────────────
Write-Status "Checking prerequisites..."

# Check Python
$python = $null
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3\.\d+") {
            $python = $cmd
            break
        }
    } catch {}
}

if (-not $python) {
    Write-Err "Python 3.8+ is required but not found."
    Write-Err "Download from: https://www.python.org/downloads/"
    Write-Err "Make sure to check 'Add Python to PATH' during installation."
    exit 1
}
Write-OK "Python found: $(& $python --version 2>&1)"

# Check network connectivity
Write-Status "Testing connection to BARAQ server..."
try {
    $healthUrl = "$Server/api/health"
    $response = Invoke-WebRequest -Uri $healthUrl -TimeoutSec 5 -UseBasicParsing
    Write-OK "Server reachable (status $($response.StatusCode))"
} catch {
    Write-Warn "Cannot reach server at $healthUrl - agent will retry on start"
}

# ── Create agent directory ───────────────────────────────────────────────
Write-Status "Setting up agent directory..."
if (-not (Test-Path $AgentDir)) {
    New-Item -ItemType Directory -Path $AgentDir -Force | Out-Null
}
Write-OK "Agent directory: $AgentDir"

# ── Download agent script ────────────────────────────────────────────────
Write-Status "Downloading agent script..."
$agentUrl = "$Server/scripts/agent.py"
try {
    Invoke-WebRequest -Uri $agentUrl -OutFile $AgentScript -TimeoutSec 30 -UseBasicParsing
    Write-OK "Agent script downloaded"
} catch {
    Write-Warn "Could not download from server, using local copy..."
    # Fallback: check if agent.py exists in a known location
    $localPaths = @(
        "$PSScriptRoot\agent.py",
        "C:\BARAQ\scripts\agent.py",
        "$env:USERPROFILE\BARAQ\scripts\agent.py"
    )
    $found = $false
    foreach ($path in $localPaths) {
        if (Test-Path $path) {
            Copy-Item $path $AgentScript -Force
            Write-OK "Agent script copied from $path"
            $found = $true
            break
        }
    }
    if (-not $found) {
        Write-Err "Could not find agent.py. Please copy scripts/agent.py to $AgentDir"
        exit 1
    }
}

# ── Create config file ───────────────────────────────────────────────────
Write-Status "Creating agent config..."
$config = @{
    server = $Server
    key = $Key
    interval = $Interval
    org = $Org
    tls_ca = ""
    no_verify = $false
} | ConvertTo-Json -Depth 3

Set-Content -Path $ConfigFile -Value $config -Encoding UTF8
Write-OK "Config saved to $ConfigFile"

# ── Register as Windows Service (Scheduled Task) ─────────────────────────
Write-Status "Registering as Windows Scheduled Task..."

# Remove existing task if present
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

# Create the task
$action = New-ScheduledTaskAction `
    -Execute "python" `
    -Argument "$AgentScript --config $ConfigFile --log $LogFile" `
    -WorkingDirectory $AgentDir

$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest -LogonType S4U

try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "BARAQ SOC telemetry agent - collects security events and sends to $Server" `
        -Force | Out-Null
    Write-OK "Scheduled task registered"
} catch {
    Write-Warn "Could not register task (run as Administrator for auto-start)"
    Write-Warn "Agent can still be run manually: python $AgentScript --config $ConfigFile"
}

# ── Start agent now ──────────────────────────────────────────────────────
Write-Status "Starting agent..."

# Test server connectivity first
try {
    $testUrl = "$Server/api/health"
    $resp = Invoke-WebRequest -Uri $testUrl -TimeoutSec 5 -UseBasicParsing
    Write-OK "Server confirmed reachable"

    # Start the task
    try {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-OK "Agent started as background task"
    } catch {
        Write-Warn "Could not start task, running agent in foreground..."
        Start-Process -FilePath "python" -ArgumentList "$AgentScript --config $ConfigFile --log $LogFile" -WindowStyle Minimized
        Write-OK "Agent started in background"
    }
} catch {
    Write-Warn "Server not reachable yet. Agent will start when server is available."
    Write-Warn "To start manually: python $AgentScript --config $ConfigFile"
}

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   BARAQ Agent Installed Successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Server:     $Server" -ForegroundColor White
Write-Host "  Department: $Org" -ForegroundColor White
Write-Host "  Agent Key:  $Key" -ForegroundColor White
Write-Host "  Interval:   ${Interval}s" -ForegroundColor White
Write-Host "  Config:     $ConfigFile" -ForegroundColor White
Write-Host "  Log:        $LogFile" -ForegroundColor White
Write-Host ""
Write-Host "  The agent will start automatically on login." -ForegroundColor Cyan
Write-Host "  Check status: Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host "  View logs:    Get-Content $LogFile -Tail 20" -ForegroundColor Cyan
Write-Host "  Uninstall:    .\install_agent.ps1 -Server $Server -Key $Key -Uninstall" -ForegroundColor Cyan
Write-Host ""
