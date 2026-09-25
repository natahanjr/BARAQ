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
    [string]$TlsCert = "",

    [Parameter(Mandatory=$false)]
    [string]$TlsCertSha256 = "",

    # The full Python agent imports backend.collectors + pywin32 and only works
    # where that stack is deployed. The self-contained PowerShell agent needs
    # nothing but Windows, so it is the default for fleet rollouts.
    [Parameter(Mandatory=$false)]
    [ValidateSet("powershell", "python")]
    [string]$AgentType = "powershell",

    [Parameter(Mandatory=$false)]
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$TaskName = "BARAQ Agent"
$AgentScript = "$AgentDir\agent.py"
$PsAgentScript = "$AgentDir\agent.ps1"
$ConfigFile = "$AgentDir\agent.config.json"
$LogFile = "$AgentDir\agent.log"

# ── Colors ────────────────────────────────────────────────────────────────
function Write-Status($msg)  { Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-OK($msg)      { Write-Host "[OK]    $msg" -ForegroundColor Green }
function Write-Warn($msg)    { Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)     { Write-Host "[ERROR] $msg" -ForegroundColor Red }

$script:ExpectedCertSha256 = $TlsCertSha256
function Invoke-BaraqRequest {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [string]$OutFile = "",
        [int]$TimeoutSec = 30
    )
    $params = @{
        Uri = $Uri
        UseBasicParsing = $true
        TimeoutSec = $TimeoutSec
        ErrorAction = "Stop"
    }
    if ($OutFile) { $params.OutFile = $OutFile }
    $restore = $null
    if ($script:ExpectedCertSha256 -and $Uri -like "https://*") {
        $pin = ($script:ExpectedCertSha256 -replace '[^0-9A-Fa-f]', '')
        if ($pin.Length -ne 64) { throw "TlsCertSha256 must be 64 hexadecimal characters" }
        $restore = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
            param($sender, $certificate, $chain, $errors)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $actual = -join ($sha.ComputeHash($certificate.GetRawCertData()) | ForEach-Object { $_.ToString("x2") })
            } finally { $sha.Dispose() }
            return ($actual -ieq $pin)
        }
    }
    try { Invoke-WebRequest @params }
    finally {
        if ($null -ne $restore) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $restore
        }
    }
}

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

# Check Python (required by the full agent; the PowerShell agent does not need it)
$python = $null
if ($AgentType -eq "python") {
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
        Write-Err "The Python agent needs Python 3.8+ but none was found."
        Write-Err "Either install Python, or re-run with -AgentType powershell."
        exit 1
    }
    Write-OK "Python found: $(& $python --version 2>&1)"
} else {
    Write-Status "Agent type: powershell (self-contained, no Python required)"
}

# Check network connectivity
Write-Status "Testing connection to BARAQ server..."
$healthUrl = "$Server/api/health"
try {
    $response = Invoke-BaraqRequest -Uri $healthUrl -TimeoutSec 5
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
function Copy-AgentScript {
    param([string]$RemotePath, [string]$DestPath, [string]$Label)
    Write-Status "Downloading $Label ..."
    try {
        Invoke-BaraqRequest -Uri "$Server$RemotePath" -OutFile $DestPath -TimeoutSec 30
        Write-OK "$Label downloaded"
        return $true
    } catch {
        Write-Warn "Could not download $Label from the server, using local copy..."
        $localPaths = @(
            "$PSScriptRoot\$([System.IO.Path]::GetFileName($RemotePath))",
            "C:\BARAQ\scripts\$([System.IO.Path]::GetFileName($RemotePath))",
            "$env:USERPROFILE\BARAQ\scripts\$([System.IO.Path]::GetFileName($RemotePath))"
        )
        foreach ($path in $localPaths) {
            if (Test-Path $path) {
                Copy-Item $path $DestPath -Force
                Write-OK "$Label copied from $path"
                return $true
            }
        }
        Write-Err "Could not find $Label. Copy scripts\$([System.IO.Path]::GetFileName($RemotePath)) to $AgentDir"
        return $false
    }
}

$usePython = ($AgentType -eq "python")
if ($usePython) {
    if (-not (Copy-AgentScript -RemotePath "/scripts/agent.py" -DestPath $AgentScript -Label "agent.py")) {
        exit 1
    }
} else {
    if (-not (Copy-AgentScript -RemotePath "/scripts/agent.ps1" -DestPath $PsAgentScript -Label "agent.ps1")) {
        exit 1
    }
}

# ── TLS certificate (self-signed / private CA) ──────────────────────────
$tlsCaPath = ""
if ($Server.StartsWith("https://")) {
    if ($TlsCert -and (Test-Path $TlsCert)) {
        $tlsCaPath = (Resolve-Path $TlsCert).Path
        Write-OK "TLS cert (local): $tlsCaPath"
    } else {
        Write-Status "Downloading TLS certificate from server..."
        $certLocal = Join-Path $AgentDir "baraq.crt"
        $certUrls = @("$Server/scripts/baraq.crt", "$Server/scripts/cert")
        $gotCert = $false
        foreach ($u in $certUrls) {
            try {
                Invoke-BaraqRequest -Uri $u -OutFile $certLocal -TimeoutSec 15
                $tlsCaPath = $certLocal
                $gotCert = $true
                Write-OK "TLS cert downloaded: $certLocal"
                break
            } catch {}
        }
        if (-not $gotCert) {
            # Fallback: local cert next to this installer (network share)
            $shareCert = Join-Path $PSScriptRoot "baraq.crt"
            if (Test-Path $shareCert) {
                Copy-Item $shareCert $certLocal -Force
                $tlsCaPath = $certLocal
                Write-OK "TLS cert copied from installer dir"
            } else {
                Write-Warn "No TLS cert found - agent will use Windows cert store."
                Write-Warn "Import certs\baraq.crt on this host, or re-run with -TlsCert."
            }
        }
    }
}

# ── Create config file ───────────────────────────────────────────────────
Write-Status "Creating agent config..."
$config = @{
    server = $Server
    key = $Key
    interval = $Interval
    org = $Org
    tls_ca = $tlsCaPath
    no_verify = $false
} | ConvertTo-Json -Depth 3

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($ConfigFile, $config, $utf8NoBom)
Write-OK "Config saved to $ConfigFile"

# ── Register as Windows Service (Scheduled Task) ─────────────────────────
Write-Status "Registering as Windows Scheduled Task..."

# Remove existing task if present
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
} catch {}

# Create the task
if ($usePython) {
    $action = New-ScheduledTaskAction `
        -Execute $python `
        -Argument ('"{0}" --config "{1}" --log "{2}"' -f $AgentScript, $ConfigFile, $LogFile) `
        -WorkingDirectory $AgentDir
} else {
        $psExe = (Get-Process -Id $PID).Path | Split-Path -Parent | Join-Path -ChildPath "powershell.exe"
        if (-not (Test-Path $psExe)) { $psExe = "powershell.exe" }
        $tlsArg = ""
        if ($tlsCaPath) { $tlsArg = ('-TlsCert "{0}"' -f $tlsCaPath) }
        $action = New-ScheduledTaskAction `
            -Execute $psExe `
            -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Server "{1}" -Key "{2}" -Org "{3}" -Interval {4} {5}' -f $PsAgentScript, $Server, $Key, $Org, $Interval, $tlsArg) `
            -WorkingDirectory $AgentDir
}

$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365)

# The task principal must be a fully-qualified account name. $env:USERNAME is
# the bare login name ("jdoe"), which Register-ScheduledTask rejects with
# HRESULT 0x80070057 on domain-joined / non-local hosts - the agent then runs
# but never comes back after a reboot. Resolve the real identity instead.
$principalId = $env:USERNAME
try {
    $principalId = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
} catch {
    Write-Warn "Could not resolve the current account name; falling back to $principalId"
}
$principal = New-ScheduledTaskPrincipal -UserId $principalId -RunLevel Highest -LogonType Interactive

$taskRegistered = $false
try {
    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Principal $principal `
        -Description "BARAQ SOC telemetry agent - collects security events and sends to $Server" `
        -Force | Out-Null
    $taskRegistered = $true
    Write-OK "Scheduled task registered"
} catch {
    Write-Warn "Could not register task as '$principalId' (run as Administrator for auto-start)"
    Write-Warn "Agent can still be run manually: python $AgentScript --config $ConfigFile"
}

# Verify the task really exists - a swallowed registration failure means the
# agent silently stops running at the next reboot.
if (-not $taskRegistered) {
    try {
        $probe = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        $taskRegistered = $null -ne $probe
    } catch {
        $taskRegistered = $false
    }
}
if (-not $taskRegistered) {
    Write-Err "AUTO-START NOT CONFIGURED. This agent will stop at the next reboot."
    Write-Err "Re-run this installer from an elevated PowerShell (Run as Administrator)."
}

# ── Start agent now ──────────────────────────────────────────────────────
Write-Status "Starting agent..."

function Start-AgentNow {
    try {
        Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Test server connectivity first
$serverReachable = $false
try {
    $resp = Invoke-BaraqRequest -Uri "$Server/api/health" -TimeoutSec 5
    Write-OK "Server confirmed reachable"
    $serverReachable = $true
} catch {
    Write-Warn "Server not reachable yet. Agent will start when server is available."
}

if ($serverReachable) {
    if (-not (Start-AgentNow)) {
        Write-Warn "Could not start the scheduled task; launching the agent directly..."
        if ($usePython) {
            Start-Process -FilePath $python -ArgumentList @("`"$AgentScript`"", "--config", "`"$ConfigFile`"", "--log", "`"$LogFile`"") -WindowStyle Minimized | Out-Null
        } else {
            $startArgs = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", "`"$PsAgentScript`"", "-Server", $Server, "-Key", $Key, "-Org", $Org, "-Interval", $Interval)
            if ($tlsCaPath) { $startArgs += @("-TlsCert", $tlsCaPath) }
            Start-Process -FilePath "powershell.exe" -ArgumentList $startArgs -WindowStyle Minimized | Out-Null
        }
    } else {
        Write-OK "Agent started as background task"
    }
}

# ── Verify the agent actually reports ─────────────────────────────────────
# An installed agent that collects nothing looks exactly like a healthy machine
# with nothing to report, so never finish with an unverified install.
$telemetryVerified = $false
if ($serverReachable) {
    Write-Status "Verifying telemetry is being accepted (up to 60s)..."
    $verifyScript = Join-Path $AgentDir "verify-once.ps1"
    if ($usePython) {
        $verifyCmd = @("`"$AgentScript`"", "--config", "`"$ConfigFile`"", "--once")
        try {
            $out = & $python @verifyCmd 2>&1 | Out-String
            if ($out -match "(?i)accepted|ingest|records|sent") { $telemetryVerified = $true }
            elseif ($out -match "(?i)no telemetry collected") {
                Write-Warn "The Python agent collected no records."
            }
        } catch {}
    } else {
        $verifyArgs = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $PsAgentScript, "-Server", $Server, "-Key", $Key, "-Interval", $Interval, "-Once")
        if ($tlsCaPath) { $verifyArgs += @("-TlsCert", $tlsCaPath) }
        $verifyOut = & powershell.exe @verifyArgs 2>&1 | Out-String
        if ($verifyOut -match "sent \d+ record") { $telemetryVerified = $true }
        if ($verifyOut -match "(?i)no records to send") {
            Write-Warn "The agent collected no records on this host (nothing to send yet)."
        }
        if ($verifyOut -match "(?i)send failed|command poll failed") {
            Write-Warn "One-shot verification reported: $($verifyOut.Trim())"
        }
    }
    if ($telemetryVerified) {
        Write-OK "Telemetry verified - the server accepted records from this host"
    } else {
        Write-Warn "Could not confirm telemetry from this host within the timeout."
        Write-Warn "Check the log and the endpoint list before trusting this host."
    }
}

# ── Summary ──────────────────────────────────────────────────────────────
Write-Host ""
$summaryTitle = if ($taskRegistered -and $telemetryVerified) {
    "   BARAQ Agent Installed and VERIFIED!"
} else {
    "   BARAQ Agent Installed - SEE WARNINGS ABOVE"
}
Write-Host "========================================" -ForegroundColor $(if ($taskRegistered -and $telemetryVerified) { "Green" } else { "Yellow" })
Write-Host $summaryTitle -ForegroundColor $(if ($taskRegistered -and $telemetryVerified) { "Green" } else { "Yellow" })
Write-Host "========================================" -ForegroundColor $(if ($taskRegistered -and $telemetryVerified) { "Green" } else { "Yellow" })
Write-Host ""
Write-Host "  Server:     $Server" -ForegroundColor White
Write-Host "  Agent type: $AgentType" -ForegroundColor White
Write-Host "  Department: $Org" -ForegroundColor White
Write-Host ("  Agent Key:  {0}..." -f $Key.Substring(0, [Math]::Min(8, $Key.Length))) -ForegroundColor White
Write-Host "  Interval:   ${Interval}s" -ForegroundColor White
Write-Host "  Config:     $ConfigFile" -ForegroundColor White
Write-Host "  Log:        $LogFile" -ForegroundColor White
Write-Host ""
if (-not $taskRegistered) {
    Write-Host "  !! AUTO-START NOT CONFIGURED - agent stops at next reboot" -ForegroundColor Red
}
if (-not $telemetryVerified) {
    Write-Host "  !! TELEMETRY NOT VERIFIED - this host may report nothing" -ForegroundColor Red
}
if ($taskRegistered -and $telemetryVerified) {
    Write-Host "  The agent will start automatically on login." -ForegroundColor Cyan
}
Write-Host "  Check status: Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
Write-Host "  View logs:    Get-Content $LogFile -Tail 20" -ForegroundColor Cyan
Write-Host "  Uninstall:    .\install_agent.ps1 -Server $Server -Key $Key -Uninstall" -ForegroundColor Cyan
Write-Host ""
