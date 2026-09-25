[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [string]$ExpectedSha256 = ""
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Version -notmatch '^\d{1,6}(\.\d{1,6}){0,3}(-[0-9A-Za-z][0-9A-Za-z._-]{0,31})?$') {
    throw "Refusing version '$Version' - expected a dotted release"
}
if ($ExpectedSha256 -and $ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
    throw "Refusing invalid -ExpectedSha256 value"
}

$Root = $PSScriptRoot
$ConfigDir = if ($env:BARAQ_AGENT_CONFIG_DIR) { $env:BARAQ_AGENT_CONFIG_DIR } else { Join-Path $env:LOCALAPPDATA "BARAQAgent" }
$Config = Join-Path $ConfigDir "agent.config.json"
$TaskName = "BARAQ Agent"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$Mutex = New-Object System.Threading.Mutex($false, "Global\BaraqAgentUpdate")
$OwnsMutex = $false
$Work = $null

function Write-UpdateLog {
    param([string]$Message)
    Write-Host "[updater] $Message"
}

function Set-RolloutState {
    param([string]$State)
    if (-not (Test-Path -LiteralPath $Config)) { return }
    try {
        $cfg = Get-Content -LiteralPath $Config -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $cfg) { return }
    } catch {
        Write-UpdateLog "config unreadable; leaving it unchanged"
        return
    }
    $cfg | Add-Member -NotePropertyName update_state -NotePropertyValue $State -Force
    $cfg | Add-Member -NotePropertyName update_version -NotePropertyValue $Version -Force
    $cfg | Add-Member -NotePropertyName update_at -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o") -Force
    [IO.File]::WriteAllText($Config, ($cfg | ConvertTo-Json -Depth 6), $Utf8NoBom)
}

try {
    try { $OwnsMutex = $Mutex.WaitOne(0) } catch { $OwnsMutex = $false }
    if (-not $OwnsMutex) {
        Write-UpdateLog "another update is already running"
        exit 3
    }

    $Url = $env:BARAQ_UPDATE_URL
    if (-not $Url) {
        Set-RolloutState "recorded"
        Write-UpdateLog "no BARAQ_UPDATE_URL configured; rollout recorded only"
        exit 0
    }
    if ($Url -notmatch '^https://') {
        throw "BARAQ_UPDATE_URL must use https://"
    }
    if (-not $ExpectedSha256) {
        throw "refusing to install an unverified bundle; provide -ExpectedSha256"
    }

    Set-RolloutState "downloading"
    $Work = Join-Path $env:TEMP ("baraq-agent-" + [guid]::NewGuid().ToString("N"))
    $Zip = Join-Path $Work "bundle.zip"
    $Staging = Join-Path $Work "staging"
    $Backup = Join-Path $Work "backup"
    New-Item -ItemType Directory -Path $Work -Force | Out-Null

    $BundleUrl = "$($Url.TrimEnd('/'))/baraq-agent-v$Version.zip"
    Write-UpdateLog "downloading $BundleUrl"
    Invoke-WebRequest -Uri $BundleUrl -OutFile $Zip -UseBasicParsing -TimeoutSec 120

    $Actual = (Get-FileHash -LiteralPath $Zip -Algorithm SHA256).Hash
    if ($Actual -ine $ExpectedSha256) {
        throw "SHA-256 mismatch: expected $ExpectedSha256, got $Actual"
    }
    Write-UpdateLog "bundle hash verified"

    Expand-Archive -LiteralPath $Zip -DestinationPath $Staging -Force
    $Allowed = @("agent.py", "agent_updater.ps1", "agent.ps1", "linux_collect.py")
    $Staged = @(Get-ChildItem -LiteralPath $Staging -File)
    if ($Staged.Count -eq 0) { throw "bundle contains no files" }
    foreach ($File in $Staged) {
        if ($Allowed -notcontains $File.Name) {
            throw "bundle contains disallowed file '$($File.Name)'"
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $Staging "agent.py"))) {
        throw "bundle is missing agent.py"
    }

    Set-RolloutState "verified"
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $Backup -Force | Out-Null
    try {
        foreach ($Name in $Allowed) {
            $Source = Join-Path $Staging $Name
            if (-not (Test-Path -LiteralPath $Source)) { continue }
            $Destination = Join-Path $Root $Name
            if (Test-Path -LiteralPath $Destination) {
                Copy-Item -LiteralPath $Destination -Destination (Join-Path $Backup $Name) -Force
            }
            Copy-Item -LiteralPath $Source -Destination $Destination -Force
        }
    } catch {
        Write-UpdateLog "swap failed; rolling back"
        foreach ($Name in $Allowed) {
            $BackupFile = Join-Path $Backup $Name
            if (Test-Path -LiteralPath $BackupFile) {
                Copy-Item -LiteralPath $BackupFile -Destination (Join-Path $Root $Name) -Force
            }
        }
        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Set-RolloutState "failed"
        throw
    }

    Start-Sleep -Seconds 1
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Set-RolloutState "applied"
    Write-UpdateLog "agent updated to $Version"
    exit 0
} catch {
    Set-RolloutState "failed"
    Write-UpdateLog "update failed: $($_.Exception.Message)"
    exit 1
} finally {
    if ($Work -and (Test-Path -LiteralPath $Work)) {
        Remove-Item -LiteralPath $Work -Recurse -Force -ErrorAction SilentlyContinue
    }
    if ($OwnsMutex -and $Mutex) {
        $Mutex.ReleaseMutex()
        $Mutex.Dispose()
    }
}
