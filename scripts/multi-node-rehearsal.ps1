param(
    [switch] $AllowMockRouter,

    [switch] $KeepStack
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")
$WorkspaceRoot = Resolve-Path (Join-Path $DevopsDir "..")
$ComposeFile = Join-Path $DevopsDir "docker-compose.yml"
$ArtifactDir = Join-Path $DevopsDir "artifacts"
$TestResultDir = Join-Path $ArtifactDir "test-results"

$env:DEEP_ROOT = $WorkspaceRoot.Path
$env:DEEP_DEVOPS_DIR = $DevopsDir.Path
$env:DEEP_COMPOSE_FILE = $ComposeFile
$env:DEEP_ARTIFACT_DIR = $TestResultDir
$env:DEEP_REGISTRY_URL = "http://127.0.0.1:18080"
$env:DEEP_MULTI_NODE_ROUTER_URLS = "http://127.0.0.1:19281,http://127.0.0.1:19282,http://127.0.0.1:19283"

if ($AllowMockRouter) {
    $env:DEEP_MULTI_NODE_REQUIRE_NO_MOCK = "false"
}
else {
    $env:DEEP_MULTI_NODE_REQUIRE_NO_MOCK = "true"
    if ([string]::IsNullOrWhiteSpace($env:XNODE_DOCKERFILE)) {
        $env:XNODE_DOCKERFILE = (Join-Path $DevopsDir "docker/xnode-xray.Dockerfile")
    }
    if ([string]::IsNullOrWhiteSpace($env:XNODE_ASPNETCORE_ENVIRONMENT)) {
        $env:XNODE_ASPNETCORE_ENVIRONMENT = "Production"
    }
    if ([string]::IsNullOrWhiteSpace($env:XNODE_VLESS_MOCK_PROCESS)) {
        $env:XNODE_VLESS_MOCK_PROCESS = "false"
    }
    if ([string]::IsNullOrWhiteSpace($env:XNODE_XRAY_EXECUTABLE_PATH)) {
        $env:XNODE_XRAY_EXECUTABLE_PATH = "/usr/local/bin/xray"
    }
    if ([string]::IsNullOrWhiteSpace($env:XNODE_TRANSPORT_MODE)) {
        $env:XNODE_TRANSPORT_MODE = "Tcp"
    }
}

New-Item -ItemType Directory -Force $TestResultDir | Out-Null

function Repair-HostArtifactOwnership {
    param(
        [string] $Path
    )

    if (-not (Test-Path $Path)) {
        return
    }

    if ($IsLinux -or $IsMacOS) {
        $uid = (& id -u).Trim()
        $gid = (& id -g).Trim()
        & sudo chown -R "${uid}:${gid}" $Path
        if ($LASTEXITCODE -ne 0) {
            throw "failed to restore artifact directory ownership for $Path"
        }

        & chmod -R u+rwX $Path
        if ($LASTEXITCODE -ne 0) {
            throw "failed to restore artifact directory permissions for $Path"
        }
    }
}

function Invoke-Docker {
    param(
        [string[]] $Arguments,
        [switch] $Quiet,
        [switch] $AllowFailure
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

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "docker $($Arguments -join ' ') failed with exit code $exitCode"
    }
}

Invoke-Docker -Arguments @("info") -Quiet -AllowFailure
if ($script:LastDockerExitCode -ne 0) {
    throw "Docker daemon is not reachable. Start Docker Desktop or the Docker service, then rerun this command."
}

try {
    Invoke-Docker -Arguments @(
        "compose",
        "-f",
        $ComposeFile,
        "--profile",
        "multi-node",
        "up",
        "--build",
        "-d",
        "--wait",
        "registry",
        "xnode-1",
        "xnode-2",
        "xnode-3"
    )

    Repair-HostArtifactOwnership -Path $ArtifactDir
    New-Item -ItemType Directory -Force $TestResultDir | Out-Null
    & node (Join-Path $ScriptDir "multi-node-rehearsal.mjs")
    if ($LASTEXITCODE -ne 0) {
        throw "multi-node rehearsal failed with exit code $LASTEXITCODE"
    }
}
catch {
    Repair-HostArtifactOwnership -Path $ArtifactDir
    & (Join-Path $ScriptDir "collect-artifacts.ps1") -ArtifactDir $ArtifactDir -ComposeFile $ComposeFile
    throw
}
finally {
    if (-not $KeepStack) {
        Invoke-Docker -Arguments @(
            "compose",
            "-f",
            $ComposeFile,
            "--profile",
            "multi-node",
            "down",
            "--volumes",
            "--remove-orphans"
        ) -AllowFailure

        if ($script:LastDockerExitCode -ne 0) {
            Write-Warning "docker compose cleanup for multi-node profile failed with exit code $script:LastDockerExitCode"
        }
    }
}
