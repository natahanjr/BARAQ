# SentinelSOC standalone telemetry agent + remote control (single file, no installation)
#
# Run on any Windows 10/11 host to stream telemetry to a central SentinelSOC
# and execute remote commands queued by the SOC operator:
#
#   powershell -ExecutionPolicy Bypass -File agent.ps1 -Server http://10.0.0.1:8000 -Key sentinel-agent-laptop2
#
# Options:
#   -Server   central SentinelSOC URL   (default http://localhost:8000)
#   -Key      agent key (X-Agent-Key)   (default sentinel-agent-laptop2)
#   -Interval seconds between cycles    (default 15)
#   -Once     send a single batch and exit (for testing / Task Scheduler)

param(
    [string]$Server = "http://localhost:8000",
    [string]$Key = "sentinel-agent-laptop2",
    [int]$Interval = 15,
    [switch]$Once
)

$ErrorActionPreference = "Stop"
$hostname = [Environment]::MachineName
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

function Send-Batch {
    $records = Get-Records
    if ($records.Count -eq 0) { Write-Host "[$hostname] no records to send"; return }

    $payload = @{ host = $hostname; records = $records } | ConvertTo-Json -Depth 6 -Compress
    $url = $Server.TrimEnd("/") + "/api/ingest"
    try {
        $resp = Invoke-RestMethod -Uri $url -Method Post -Headers @{ "X-Agent-Key" = $Key } -ContentType "application/json" -Body $payload -TimeoutSec 20
        Write-Host ("[{0}] sent {1} record(s) -> saved_events={2} alerts={3}" -f $hostname, $records.Count, $resp.saved_events, $resp.alerts_created)
    } catch {
        Write-Host ("[{0}] send failed: {1}" -f $hostname, $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# Remote control: poll the SOC server for pending commands, execute, report back.
# ---------------------------------------------------------------------------

function Invoke-Command {
    param([hashtable]$Command)
    $action = [string]$Command.action
    $target = [string]$Command.target
    Write-Host ("[{0}] executing {1} {2}" -f $hostname, $action, $target)
    try {
        switch ($action) {
            "block_ip" {
                $rule = "SentinelSOC Block $target"
                & netsh advfirewall firewall add rule name=$rule dir=in action=block remoteip=$target enable=yes | Out-Null
                & netsh advfirewall firewall add rule name=$rule dir=out action=block remoteip=$target enable=yes | Out-Null
                return @{ status = "success"; detail = "blocked $target (in+out)" }
            }
            "kill_process" {
                Get-Process -Name $target -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction Stop
                return @{ status = "success"; detail = "killed process $target" }
            }
            "quarantine" {
                if (-not (Test-Path -LiteralPath $target)) { return @{ status = "failed"; detail = "path not found: $target" } }
                $quarantine = Join-Path $env:SystemDrive "SentinelSOC-Quarantine"
                if (-not (Test-Path -LiteralPath $quarantine)) { New-Item -ItemType Directory -Path $quarantine | Out-Null }
                Move-Item -LiteralPath $target -Destination $quarantine -Force
                return @{ status = "success"; detail = "quarantined $target" }
            }
            "escalate" {
                Write-Host "[$hostname] ESCALATION flagged - operator review required"
                return @{ status = "success"; detail = "Acknowledged" }
            }
            default { return @{ status = "failed"; detail = "unknown action: $action" } }
        }
    } catch {
        return @{ status = "failed"; detail = $_.Exception.Message }
    }
}

function Invoke-PendingCommands {
    $url = $Server.TrimEnd("/") + "/api/commands/pending"
    try {
        $pending = Invoke-RestMethod -Uri $url -Method Get -Headers @{ "X-Agent-Key" = $Key } -TimeoutSec 20
        foreach ($cmd in $pending.items) {
            $report = Invoke-Command $cmd
            $resultUrl = $Server.TrimEnd("/") + ("/api/commands/{0}/result" -f $cmd.id)
            Invoke-RestMethod -Uri $resultUrl -Method Post -Headers @{ "X-Agent-Key" = $Key } -ContentType "application/json" `
                -Body (@{ status = $report.status; detail = $report.detail } | ConvertTo-Json -Compress) -TimeoutSec 20 | Out-Null
            Write-Host ("[{0}] command #{1} -> {2}" -f $hostname, $cmd.id, $report.status)
        }
    } catch {
        Write-Host ("[{0}] command poll failed: {1}" -f $hostname, $_.Exception.Message)
    }
}

Write-Host "[$hostname] SentinelSOC agent starting -> $Server (key: $Key)"
do {
    Invoke-PendingCommands
    Send-Batch
    if ($Once) { break }
    Start-Sleep -Seconds $Interval
} while ($true)
