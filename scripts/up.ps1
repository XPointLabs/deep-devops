param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")
$WorkspaceRoot = Resolve-Path (Join-Path $DevopsDir "..")

$env:DEEP_ROOT = $WorkspaceRoot.Path
$env:DEEP_DEVOPS_DIR = $DevopsDir.Path
$env:DEEP_TESTS_DIR = (Resolve-Path (Join-Path $WorkspaceRoot "deep-tests-e2e")).Path

function Invoke-Docker {
    param(
        [string[]] $Arguments,
        [switch] $Quiet
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    if ($Quiet) {
        & docker @Arguments *> $null
    }
    else {
        & docker @Arguments
    }
    $exitCode = $LASTEXITCODE
    $ErrorActionPreference = $previousErrorActionPreference
    $script:LastDockerExitCode = $exitCode
}

Invoke-Docker -Arguments @("info") -Quiet
if ($script:LastDockerExitCode -ne 0) {
    throw "Docker daemon is not reachable. Start Docker Desktop or the Docker service, then rerun this command."
}

Invoke-Docker -Arguments @("compose", "-f", (Join-Path $DevopsDir "docker-compose.yml"), "up", "--build", "-d", "xnode", "registry", "staking-backend", "contracts-devnet", "storage", "file", "push")
if ($script:LastDockerExitCode -ne 0) {
    throw "docker compose up failed with exit code $script:LastDockerExitCode"
}
