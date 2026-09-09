param(
    [switch] $AllowMockRouter,

    [switch] $KeepStack
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")
$WorkspaceRoot = Resolve-Path (Join-Path $DevopsDir "..")
$ComposeFile = Join-Path $DevopsDir "docker-compose.yml"
$ArtifactRoot = Join-Path $DevopsDir "artifacts"
$RunId = '{0}-{1}' -f ([DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')), ([Guid]::NewGuid().ToString('N').Substring(0, 12))
$ArtifactDir = Join-Path $ArtifactRoot (Join-Path 'rehearsals\multi-node' $RunId)
$TestResultDir = Join-Path $ArtifactDir "test-results"
$ComposeProjectName = "deep-multi-node-rehearsal"
$ComposeTimeoutSeconds = 900
if (-not [string]::IsNullOrWhiteSpace($env:DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS)) {
    $parsedTimeout = 0
    if (-not [int]::TryParse($env:DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS, [ref]$parsedTimeout) -or
        $parsedTimeout -lt 60 -or $parsedTimeout -gt 1800) {
        throw "DEEP_MULTI_NODE_COMPOSE_TIMEOUT_SECONDS must be an integer from 60 through 1800"
    }
    $ComposeTimeoutSeconds = $parsedTimeout
}

$env:DEEP_ROOT = $WorkspaceRoot.Path
$env:DEEP_DEVOPS_DIR = $DevopsDir.Path
$env:DEEP_COMPOSE_FILE = $ComposeFile
$env:DEEP_ARTIFACT_DIR = $TestResultDir
$env:DEEP_REHEARSAL_RUN_DIR = $ArtifactDir
$env:DEEP_REGISTRY_URL = "http://127.0.0.1:18080"
$env:DEEP_MULTI_NODE_ROUTER_URLS = "http://127.0.0.1:19281,http://127.0.0.1:19282,http://127.0.0.1:19283"
. (Join-Path $ScriptDir "ephemeral-compose-secrets.ps1")
$generatedComposeSecretNames = @(Initialize-DeepEphemeralComposeSecrets -ScriptDirectory $ScriptDir)

if ($AllowMockRouter) {
    $env:DEEP_MULTI_NODE_REQUIRE_NO_MOCK = "false"
}
else {
    $env:DEEP_MULTI_NODE_REQUIRE_NO_MOCK = "true"
    if ([string]::IsNullOrWhiteSpace($env:XNODE_DOCKERFILE)) {
        $env:XNODE_DOCKERFILE = (Join-Path $DevopsDir "docker/xnode-xray.Dockerfile")
    }
    if ([string]::IsNullOrWhiteSpace($env:XNODE_ASPNETCORE_ENVIRONMENT)) {
        # This is a development no-mock transport lane. Production XNode is
        # intentionally DenyAll until verified ownership tickets are wired.
        $env:XNODE_ASPNETCORE_ENVIRONMENT = "Development"
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
    if ($null -eq $exitCode -or -not ($exitCode -is [int])) {
        $exitCode = 125
    }
    $script:LastDockerExitCode = $exitCode

    if ($exitCode -ne 0 -and -not $AllowFailure) {
        throw "docker $($Arguments -join ' ') failed with exit code $exitCode"
    }
}

function Invoke-DockerBounded {
    param(
        [string[]] $Arguments,
        [int] $TimeoutSeconds
    )

    $runId = [Guid]::NewGuid().ToString("N")
    $stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) "deep-docker-$runId.stdout.log"
    $stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) "deep-docker-$runId.stderr.log"
    $process = $null
    try {
        Write-Host "Starting bounded docker command (timeout ${TimeoutSeconds}s): docker $($Arguments -join ' ')"
        $startProcessParameters = @{
            FilePath = "docker"
            ArgumentList = $Arguments
            PassThru = $true
            RedirectStandardOutput = $stdoutPath
            RedirectStandardError = $stderrPath
        }
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $startProcessParameters.WindowStyle = 'Hidden'
        }
        $process = Start-Process @startProcessParameters
        # Windows PowerShell can lose ExitCode for a quickly-exiting child if
        # the native handle was never materialized before WaitForExit.
        [void]$process.Handle
        $startedAt = [DateTimeOffset]::UtcNow
        $nextProgressAt = $startedAt.AddSeconds(15)
        while (-not $process.WaitForExit(1000)) {
            $now = [DateTimeOffset]::UtcNow
            $elapsedSeconds = [int]($now - $startedAt).TotalSeconds
            if ($elapsedSeconds -ge $TimeoutSeconds) {
                try {
                    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                        & taskkill.exe /PID $process.Id /T /F *> $null
                    } else {
                        $process.Kill()
                    }
                } catch { Write-Warning "failed to terminate timed-out docker process tree: $_" }
                $process.WaitForExit()
                foreach ($path in @($stdoutPath, $stderrPath)) {
                    if (Test-Path $path) { Get-Content $path -Tail 40 }
                }
                throw "docker command exceeded bounded timeout of ${TimeoutSeconds}s"
            }
            if ($now -ge $nextProgressAt) {
                Write-Host "docker compose is still running (${elapsedSeconds}s elapsed)"
                foreach ($path in @($stdoutPath, $stderrPath)) {
                    if (Test-Path $path) { Get-Content $path -Tail 8 }
                }
                $nextProgressAt = $now.AddSeconds(15)
            }
        }
        $process.WaitForExit()
        $process.Refresh()
        $rawExitCode = $process.ExitCode
        if ($null -eq $rawExitCode -or -not ($rawExitCode -is [int])) {
            throw "docker process completed without an observable integer exit code"
        }
        $exitCode = [int]$rawExitCode
        $script:LastDockerExitCode = $exitCode
        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path $path) { Get-Content $path }
        }
        if ($exitCode -ne 0) {
            throw "docker $($Arguments -join ' ') failed with exit code $exitCode"
        }
    }
    finally {
        foreach ($path in @($stdoutPath, $stderrPath)) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Invoke-DockerCleanupBounded {
    param(
        [string[]] $Arguments,
        [int] $Attempts = 6,
        [int] $DelaySeconds = 5
    )

    foreach ($attempt in 1..$Attempts) {
        Invoke-Docker -Arguments $Arguments -Quiet -AllowFailure
        if ($script:LastDockerExitCode -eq 0) {
            return $true
        }
        if ($attempt -lt $Attempts) {
            Write-Warning "docker cleanup attempt $attempt/$Attempts failed with exit code $script:LastDockerExitCode; retrying after ${DelaySeconds}s"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
    return $false
}

Invoke-Docker -Arguments @("info") -Quiet -AllowFailure
if ($script:LastDockerExitCode -ne 0) {
    throw "Docker daemon is not reachable. Start Docker Desktop or the Docker service, then rerun this command."
}

try {
    # A prior interrupted rehearsal must never make the next run wait on stale
    # project state. The fixed, isolated project name cannot address the live
    # survival-dev stack.
    Invoke-Docker -Arguments @(
        "compose",
        "-p",
        $ComposeProjectName,
        "-f",
        $ComposeFile,
        "--profile",
        "multi-node",
        "down",
        "--volumes",
        "--remove-orphans"
    ) -Quiet -AllowFailure

    Invoke-DockerBounded -TimeoutSeconds $ComposeTimeoutSeconds -Arguments @(
        "compose",
        "--progress",
        "plain",
        "-p",
        $ComposeProjectName,
        "-f",
        $ComposeFile,
        "--profile",
        "multi-node-build",
        "build",
        "xnode-multi-node-image",
        "registry"
    )

    Invoke-DockerBounded -TimeoutSeconds 300 -Arguments @(
        "compose",
        "--progress",
        "plain",
        "-p",
        $ComposeProjectName,
        "-f",
        $ComposeFile,
        "--profile",
        "multi-node",
        "up",
        "--no-build",
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
    $primaryError = $_
    Repair-HostArtifactOwnership -Path $ArtifactDir
    try {
        & (Join-Path $ScriptDir "collect-artifacts.ps1") `
            -ArtifactDir $ArtifactDir `
            -ComposeFile $ComposeFile `
            -ComposeProjectName $ComposeProjectName
    } catch {
        Write-Warning "isolated failure collection failed: $($_.Exception.Message)"
    }
    throw $primaryError
}
finally {
    if (-not $KeepStack) {
        $cleanupSucceeded = Invoke-DockerCleanupBounded -Arguments @(
            "compose",
            "-p",
            $ComposeProjectName,
            "-f",
            $ComposeFile,
            "--profile",
            "multi-node",
            "down",
            "--volumes",
            "--remove-orphans"
        )

        if (-not $cleanupSucceeded) {
            Write-Warning "docker compose cleanup for multi-node profile failed with exit code $script:LastDockerExitCode"
        }
    }
    Clear-DeepEphemeralComposeSecrets -GeneratedNames $generatedComposeSecretNames
}

Write-Output "Multi-node rehearsal run directory: $ArtifactDir"
