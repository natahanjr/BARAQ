<#
.SYNOPSIS
    Blue-green release switch for the BARAQ API tier (roadmap 5.1).

.DESCRIPTION
    Determines which release the baraq-api Service currently routes to,
    deploys the new image into the idle release, waits for rollout +
    readiness, then flips the Service selector. On any failure the switch is
    aborted and the active release keeps serving. Running the script again
    flips back (rollback) to the previously drained release.

.PARAMETER Image
    Container image to deploy into the idle release (default baraq/soc:latest).

.PARAMETER Namespace
    Kubernetes namespace (default "default").

.EXAMPLE
    .\scripts\blue_green_switch.ps1 -Image ghcr.io/org/baraq:1.2.3

.EXAMPLE
    .\scripts\blue_green_switch.ps1            # rollback: flip back
#>
[CmdletBinding()]
param(
    [string]$Image = "baraq/soc:latest",
    [string]$Namespace = "default"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
    throw "kubectl is required on PATH"
}

$svc = "baraq-api"

# 1) Which release is serving right now?
$active = (kubectl get "service/$svc" -n $Namespace -o jsonpath="{.spec.selector.release}")
if (-not $active -or ($active -notin @("blue", "green"))) {
    throw "Cannot determine the active release (got '$active')"
}
$inactive = if ($active -eq "blue") { "green" } else { "blue" }
Write-Host "Active: '$active' - deploying new build into idle release '$inactive'"

$idleDeploy = "baraq-api-$inactive"
$oldDeploy = "baraq-api-$active"

# 2) Deploy the new image into the idle release (traffic still on $active).
kubectl set image "deployment/$idleDeploy" "api=$Image" -n $Namespace
if ($LASTEXITCODE -ne 0) { throw "kubectl set image failed for $idleDeploy" }
kubectl scale "deployment/$idleDeploy" --replicas=2 -n $Namespace
Write-Host "Waiting for rollout of $idleDeploy..."
kubectl rollout status "deployment/$idleDeploy" -n $Namespace --timeout=180s
if ($LASTEXITCODE -ne 0) { throw "Rollout of $idleDeploy failed" }

# 3) Validate the idle release is serving before any traffic moves.
kubectl wait --for=condition=Available "deployment/$idleDeploy" -n $Namespace --timeout=180s
if ($LASTEXITCODE -ne 0) { throw "$idleDeploy is not available - aborting switch" }

# 4) Flip the Service selector (atomic; traffic moves in one API call).
Write-Host "Switching traffic to '$inactive'..."
kubectl patch "service/$svc" -n $Namespace --type=merge -p `
    "{""spec"":{""selector"":{""app"":""baraq"",""tier"":""api"",""release"":""$inactive""}}}"
if ($LASTEXITCODE -ne 0) { throw "Service switch failed - '$active' is still serving" }

# 5) Drain the previous release.
kubectl scale "deployment/$oldDeploy" --replicas=0 -n $Namespace

Write-Host "Blue-green switch complete: '$inactive' is now live, '$active' drained."
Write-Host "Rollback: re-run .\scripts\blue_green_switch.ps1 (with -Image pointing at the previous build)"