# BARAQ dashboard waiter: polls /api/health until the backend is ready,
# then opens the browser. Never opens the browser before the app is up.
param(
    [string]$Url = "http://127.0.0.1:8001",
    [int]$TimeoutSeconds = 180
)
$ErrorActionPreference = "SilentlyContinue"
$health = "$Url/api/health"
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
$ready = $false
while ([DateTime]::UtcNow -lt $deadline) {
    try {
        $r = Invoke-WebRequest -Uri $health -UseBasicParsing -TimeoutSec 3
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
}
if ($ready) {
    Start-Process $Url
} else {
    Write-Host "[WARN] Dashboard did not become ready within $TimeoutSeconds s."
    Write-Host "       Check the launcher window for errors (e.g. PostgreSQL not started)."
}