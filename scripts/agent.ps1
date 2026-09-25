# BARAQ standalone telemetry agent + remote control (single file, no installation)
#
# LIGHTWEIGHT MODE — This PowerShell agent collects basic process and network
# telemetry. For full telemetry coverage (Windows Event Logs, Sysmon, DNS,
# USB, registry, scheduled tasks, PowerShell transcripts), deploy the full
# Python agent via scripts/install_agent.ps1.
#
# Run on any Windows 10/11 host to stream telemetry to a central BARAQ
# and execute remote commands queued by the SOC operator:
#
#   powershell -ExecutionPolicy Bypass -File agent.ps1 -Server http://10.0.0.1:8001 -Key YOUR-AGENT-KEY
#
# Options:
#   -Server   central BARAQ URL   (default http://localhost:8001)
#   -Key      agent key (X-Agent-Key)   (required — no default, use your provisioned key)
#   -Interval seconds between cycles    (default 15)
#   -Once     send a single batch and exit (for testing / Task Scheduler)

param(
    [string]$Server = "http://localhost:8001",
    [string]$Key = "",
    [int]$Interval = 15,
    # Pin the server certificate (PEM). Self-signed / private-CA deployments
    # otherwise fail the TLS handshake, and the fix operators reach for first
    # is disabling validation - which removes all transport security.
    [string]$TlsCert = "",
    [switch]$Once
)

$ErrorActionPreference = "Stop"

$hostname = [Environment]::MachineName

# The installer tells operators to read agent.log, but this agent runs hidden
# with no console - without a file the only way to diagnose a silent agent is to
# attach a debugger. Mirrors the Python agent's log file. Defined before any
# other code so early failures can be logged too.
$LogFile = Join-Path $env:LOCALAPPDATA "BARAQAgent\agent.log"
function Write-Log {
    param(
        [Parameter(Mandatory=$true, Position=0)][string]$Message,
        [string]$Level = "INFO",
        # Accepted (and ignored) so the call sites keep their console colours.
        [string]$ForegroundColor = ""
    )
    try {
        $dir = Split-Path -Parent $LogFile
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $line = "{0} | {1,-5} | agent | {2}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Level, $Message
        Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    Write-Host $Message
}

# Validate the server certificate against the pinned thumbprint instead of the
# machine store. .NET 5+ (PowerShell 7) uses ServerCertificateCustomValidationCallback;
# Windows PowerShell 5.1 uses ServerCertificateValidationCallback.
$pinnedThumb = ""
if ($Server.StartsWith("https://")) {
    if (-not $TlsCert -or -not (Test-Path $TlsCert)) {
        Write-Log "ERROR: https:// requires -TlsCert <path to baraq.crt> (or import the CA into the machine store)." -ForegroundColor Red
        exit 1
    }
    try {
        $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2((Resolve-Path $TlsCert).Path)
        $pinnedThumb = $certObj.Thumbprint
        Write-Log ("[{0}] pinning server certificate {1}" -f $hostname, $pinnedThumb)
    } catch {
        Write-Log "ERROR: could not read certificate $TlsCert - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }

    $validate = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($senderObj, $certificate, $chain, $sslPolicyErrors)
        if (-not $certificate) { return $false }
        return $certificate.GetCertHashString() -eq $pinnedThumb
    }
    try {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $validate
        # Windows PowerShell 5.1 fails the first request of a pooled TLS
        # connection with "An unexpected error occurred on a send" unless these
        # are set; that broke command polling while ingest still worked.
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::Expect100Continue = $false
    } catch {
        Write-Log "ERROR: could not install the certificate pin callback - $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

if (-not $Key) {
    Write-Log "ERROR: No agent key provided. Run with -Key YOUR-AGENT-KEY" -ForegroundColor Red
    Write-Log "Usage: powershell -ExecutionPolicy Bypass -File agent.ps1 -Server http://YOUR-SERVER:8001 -Key YOUR-AGENT-KEY" -ForegroundColor Yellow
    exit 1
}

$seenProcesses = @{}

function Get-Records {
    $records = @()

    # --- Processes (only new ones, like the full agent) ---
    $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Select-Object -First 300)
    $nameById = @{}
    foreach ($p in $procs) { $nameById[[int]$p.ParentProcessId] = [string]$p.Name }
    foreach ($p in $procs) {
        $procId = [int]$p.ProcessId
        $sig = "$procId|$($p.Name)"
        if ($seenProcesses.ContainsKey($sig)) { continue }
        $seenProcesses[$sig] = $true
        $records += @{
            source        = "process"
            pid           = $procId
            ppid          = [int]$p.ParentProcessId
            name          = [string]$p.Name
            path          = [string]$p.ExecutablePath
            command_line  = [string]$p.CommandLine
            parent_name   = [string]$nameById[[int]$p.ParentProcessId]
            user          = "-"
            is_new        = $true
            timestamp     = [DateTime]::UtcNow.ToString("o")
        }
    }

    # --- Active TCP connections ---
    $conns = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -in @("Established", "Listen", "TimeWait") } |
        Select-Object -First 200)
    foreach ($c in $conns) {
        $records += @{
            source        = "network"
            pid           = [int]$c.OwningProcess
            process       = ""
            local_ip      = [string]$c.LocalAddress
            local_port    = [int]$c.LocalPort
            remote_ip     = [string]$c.RemoteAddress
            remote_port   = [int]$c.RemotePort
            state         = [string]$c.State
            is_listening  = ($c.State -eq "Listen")
            bytes_sent    = 0
            bytes_recv    = 0
            duration_seconds = 0.0
            timestamp     = [DateTime]::UtcNow.ToString("o")
        }
    }

    return $records
}

function Invoke-BaraqApi {
    # Invoke-RestMethod / Invoke-WebRequest fail with "The underlying connection
    # was closed: An unexpected error occurred on a send" for GET over TLS on
    # Windows PowerShell 5.1 (observed on a real host), which silently killed
    # command polling. System.Net.HttpWebRequest works, so the agent uses it
    # directly for every call.
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [string]$Method = "GET",
        [string]$Body = "",
        [int]$TimeoutSec = 30
    )
    $url = $Server.TrimEnd("/") + $Path
    $request = [System.Net.HttpWebRequest]::Create($url)
    $request.Method = $Method
    $request.Timeout = $TimeoutSec * 1000
    $request.ReadWriteTimeout = $TimeoutSec * 1000
    $request.UserAgent = "BARAQ-Agent"
    $request.Headers.Add("X-Agent-Key", $Key)
    $request.Accept = "application/json"
    if ($Body) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $request.ContentType = "application/json"
        $request.ContentLength = $bytes.Length
        $stream = $request.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    $response = $request.GetResponse()
    try {
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $text = $reader.ReadToEnd()
        $reader.Close()
    } finally {
        $response.Close()
    }
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
}

function Send-Batch {
    $records = Get-Records
    if ($records.Count -eq 0) { Write-Log "[$hostname] no records to send"; return }

    $payload = @{ host = $hostname; records = $records } | ConvertTo-Json -Depth 6 -Compress
    try {
        # Ingest runs the detection pipeline server-side, so allow a long budget.
        $resp = Invoke-BaraqApi -Path "/api/ingest" -Method POST -Body $payload -TimeoutSec 300
        Write-Log ("[{0}] sent {1} record(s) -> saved_events={2} alerts={3}" -f $hostname, $records.Count, $resp.saved_events, $resp.alerts_created)
    } catch {
        Write-Log ("[{0}] send failed: {1}" -f $hostname, $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# Remote control: poll the SOC server for pending commands, execute, report back.
# ---------------------------------------------------------------------------

function Invoke-Command {
    param([hashtable]$Command)
    $action = [string]$Command.action
    $target = [string]$Command.target
    Write-Log ("[{0}] executing {1} {2}" -f $hostname, $action, $target)
    try {
        switch ($action) {
            "block_ip" {
                # One rule name per direction, tagged with the target so an
                # unblock (or a cleanup sweep) can find it deterministically.
                $stamp = (Get-Date).ToString("yyyyMMddHHmmss")
                $inRule = "BARAQ-SOAR-IN-$($target -replace '\.','-')"
                $outRule = "BARAQ-SOAR-OUT-$($target -replace '\.','-')"
                & netsh advfirewall firewall add rule name=$inRule dir=in action=block remoteip=$target enable=yes | Out-Null
                & netsh advfirewall firewall add rule name=$outRule dir=out action=block remoteip=$target enable=yes | Out-Null
                return @{ status = "success"; detail = "blocked $target (in+out) at $stamp" }
            }
            "unblock_ip" {
                $inRule = "BARAQ-SOAR-IN-$($target -replace '\.','-')"
                $outRule = "BARAQ-SOAR-OUT-$($target -replace '\.','-')"
                $removed = 0
                foreach ($r in @($inRule, $outRule)) {
                    & netsh advfirewall firewall delete rule name=$r | Out-Null
                    if ($LASTEXITCODE -eq 0) { $removed++ }
                }
                # Also clear any legacy "BARAQ Block <ip>" rules.
                & netsh advfirewall firewall delete rule name="BARAQ Block $target" | Out-Null
                if ($removed -eq 0) {
                    return @{ status = "failed"; detail = "no BARAQ block rules found for $target" }
                }
                return @{ status = "success"; detail = "unblocked $target ($removed rule(s) removed)" }
            }
            "kill_process" {
                Get-Process -Name $target -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
                return @{ status = "success"; detail = "killed process $target" }
            }
            "quarantine" {
                if (-not (Test-Path -LiteralPath $target)) { return @{ status = "failed"; detail = "path not found: $target" } }
                $quarantine = Join-Path $env:SystemDrive "BARAQ-Quarantine"
                if (-not (Test-Path -LiteralPath $quarantine)) { New-Item -ItemType Directory -Path $quarantine | Out-Null }
                Move-Item -LiteralPath $target -Destination $quarantine -Force
                return @{ status = "success"; detail = "quarantined $target" }
            }
            "escalate" {
                Write-Log "[$hostname] ESCALATION flagged - operator review required"
                return @{ status = "success"; detail = "Acknowledged" }
            }
            "update_agent" {
                $updater = Join-Path $PSScriptRoot "agent_updater.ps1"
                if (Test-Path -LiteralPath $updater) {
                    & $updater -Version $target
                    return @{ status = "success"; detail = "updated to $target via agent_updater.ps1" }
                }
                return @{ status = "success"; detail = "target version $target recorded (no updater configured)" }
            }
            default { return @{ status = "failed"; detail = "unknown action: $action" } }
        }
    } catch {
        return @{ status = "failed"; detail = $_.Exception.Message }
    }
}

function Invoke-PendingCommands {
    try {
        $pending = Invoke-BaraqApi -Path "/api/commands/pending" -Method GET -TimeoutSec 30
        foreach ($cmd in $pending.items) {
            $report = Invoke-Command $cmd
            $resultBody = @{ status = $report.status; detail = $report.detail } | ConvertTo-Json -Compress
            Invoke-BaraqApi -Path ("/api/commands/{0}/result" -f $cmd.id) -Method POST -Body $resultBody -TimeoutSec 30 | Out-Null
            Write-Log ("[{0}] command #{1} -> {2}" -f $hostname, $cmd.id, $report.status)
        }
    } catch {
        Write-Log ("[{0}] command poll failed: {1}" -f $hostname, $_.Exception.Message)
    }
}

Write-Log "[$hostname] BARAQ agent starting -> $Server (key: $Key)"
do {
    Invoke-PendingCommands
    Send-Batch
    if ($Once) { break }
    Start-Sleep -Seconds $Interval
} while ($true)
