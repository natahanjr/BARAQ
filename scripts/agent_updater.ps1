# BARAQ agent auto-update (roadmap 3.4 fleet)
# Invoked by the agent when the SOC queues an update_agent command:
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File agent_updater.ps1 -Version 2.0.0
#
# Behavior:
#   - if $env:BARAQ_UPDATE_URL is set, downloads <URL>/baraq-agent-v<VERSION>.zip
#     and swaps the agent files, then restarts the "BARAQ Agent" scheduled task;
#   - otherwise it only records the rollout target in agent.config.json
#     (no real update source configured).
param(
    [Parameter(Mandatory = $true)]
    [string]$Version
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$ConfigDir = if ($env:BARAQ_AGENT_CONFIG_DIR) { $env:BARAQ_AGENT_CONFIG_DIR } else { Join-Path $env:LOCALAPPDATA "BARAQAgent" }
$Config = Join-Path $ConfigDir "agent.config.json"
$TaskName = "BARAQ Agent"

function Write-Rollout {
    param([string]$State)
    if (Test-Path -LiteralPath $Config) {
        try {
            $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
        } catch { $cfg = [pscustomobject]@{} }
        $cfg | Add-Member -NotePropertyName update_state -NotePropertyValue $State -Force
        $cfg | Add-Member -NotePropertyName update_version -NotePropertyValue $Version -Force
        $cfg | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Config -Encoding UTF8
    }
}

$Url = $env:BARAQ_UPDATE_URL
if (-not $Url) {
    Write-Rollout "recorded"
    Write-Host "No BARAQ_UPDATE_URL configured - rollout to $Version recorded only"
    exit 0
}

$Zip = Join-Path $env:TEMP "baraq-agent-v$Version.zip"
$Staging = Join-Path $env:TEMP "baraq-agent-v$Version"
try {
    Write-Host "Downloading $Url/baraq-agent-v$Version.zip ..."
    Invoke-WebRequest -Uri "$Url/baraq-agent-v$Version.zip" -OutFile $Zip -UseBasicParsing -TimeoutSec 120
    if (Test-Path -LiteralPath $Staging) { Remove-Item -LiteralPath $Staging -Recurse -Force }
    Expand-Archive -LiteralPath $Zip -DestinationPath $Staging -Force

    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath (Join-Path $Staging "*.py") -Destination $Root -Recurse -Force
    Copy-Item -LiteralPath (Join-Path $Staging "scripts\*") -Destination (Join-Path $Root "scripts") -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    Write-Rollout "applied"
    Write-Host "Agent updated to $Version"
    exit 0
} catch {
    Write-Rollout "failed"
    Write-Host "Update failed: $($_.Exception.Message)"
    exit 1
}
