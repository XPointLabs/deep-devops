param(
    [ValidateSet("smoke", "full")]
    [string] $Suite = $(if ($env:E2E_SUITE) { $env:E2E_SUITE } else { "smoke" }),

    [ValidateSet("compat", "external")]
    [string] $BackendMode = $(if ($env:DEEP_BACKEND_MODE) { $env:DEEP_BACKEND_MODE } else { "compat" }),

    [string] $ManagedExternalProfile = $(if ($env:DEEP_EXTERNAL_PROFILE) { $env:DEEP_EXTERNAL_PROFILE } else { "" }),

    [switch] $RequireRouterNoMock,

    [switch] $RequirePushProviderCanary
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DevopsDir = Resolve-Path (Join-Path $ScriptDir "..")
$WorkspaceRoot = Resolve-Path (Join-Path $DevopsDir "..")
$ComposeFile = Join-Path $DevopsDir "docker-compose.yml"
$ArtifactDir = Join-Path $DevopsDir "artifacts"

$env:DEEP_ROOT = $WorkspaceRoot.Path
$env:DEEP_DEVOPS_DIR = $DevopsDir.Path
$env:DEEP_TESTS_DIR = (Resolve-Path (Join-Path $WorkspaceRoot "deep-tests-e2e")).Path
$env:DEEP_COMPOSE_FILE = $ComposeFile
$env:E2E_SUITE = $Suite
$env:DEEP_BACKEND_MODE = $BackendMode
. (Join-Path $ScriptDir "ephemeral-compose-secrets.ps1")
$generatedComposeSecretNames = @(Initialize-DeepEphemeralComposeSecrets -ScriptDirectory $ScriptDir)

if (-not $RequireRouterNoMock -and ($env:DEEP_REQUIRE_ROUTER_NO_MOCK -match '^(1|true|yes)$')) {
    $RequireRouterNoMock = $true
}

if (-not $RequirePushProviderCanary -and ($env:DEEP_REQUIRE_PUSH_PROVIDER_CANARY -match '^(1|true|yes)$')) {
    $RequirePushProviderCanary = $true
}

New-Item -ItemType Directory -Force $ArtifactDir | Out-Null

$SuiteCompletedSuccessfully = $false
$managedExternalServices = @()

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

function Set-DefaultProcessEnvironmentVariable {
    param(
        [string] $Name,
        [string] $Value
    )

    if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($Name))) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
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

if ($RequireRouterNoMock) {
    Set-DefaultProcessEnvironmentVariable -Name "XNODE_DOCKERFILE" -Value (Join-Path $DevopsDir "docker/xnode-xray.Dockerfile")
    # This integration lane proves that the real Xray process and transport are
    # healthy. Production readiness is a separate fail-closed authority gate;
    # enabling that profile here would intentionally keep privacy routing down.
    Set-DefaultProcessEnvironmentVariable -Name "XNODE_ASPNETCORE_ENVIRONMENT" -Value "Development"
    Set-DefaultProcessEnvironmentVariable -Name "XNODE_VLESS_MOCK_PROCESS" -Value "false"
    Set-DefaultProcessEnvironmentVariable -Name "XNODE_XRAY_EXECUTABLE_PATH" -Value "/usr/local/bin/xray"
    Set-DefaultProcessEnvironmentVariable -Name "XNODE_TRANSPORT_MODE" -Value "Tcp"
}

$managedServices = @("xnode", "registry", "staking-backend", "contracts-devnet")
if (-not [string]::IsNullOrWhiteSpace($ManagedExternalProfile) -and $BackendMode -ne "external") {
    throw "ManagedExternalProfile requires BackendMode=external"
}

if ($RequirePushProviderCanary -and $BackendMode -ne "external") {
    throw "RequirePushProviderCanary requires BackendMode=external"
}

if ($BackendMode -eq "compat") {
    Set-DefaultProcessEnvironmentVariable -Name "DEEP_CALL_SIGNALING_BASE_URL" -Value "http://calls:8080"
    $managedServices += @("storage", "file", "push", "calls")
}
else {
    if (-not [string]::IsNullOrWhiteSpace($ManagedExternalProfile)) {
        if ($ManagedExternalProfile -ne "backend-external") {
            throw "Unsupported ManagedExternalProfile: $ManagedExternalProfile"
        }

        Set-DefaultProcessEnvironmentVariable -Name "DEEP_STORAGE_URL" -Value "http://host.docker.internal:19100"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_FILE_URL" -Value "http://host.docker.internal:19101"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_PUSH_URL" -Value "http://host.docker.internal:19102"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_STORAGE_STATS_URL" -Value "http://127.0.0.1:19100/stats"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_FILE_STATS_URL" -Value "http://127.0.0.1:19101/stats"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_PUSH_STATS_URL" -Value "http://127.0.0.1:19102/stats"
        Set-DefaultProcessEnvironmentVariable -Name "DEEP_STORAGE_PUSH_NOTIFY_URL" -Value "http://push-service:8080"
        [Environment]::SetEnvironmentVariable("DEEP_EXTERNAL_PROFILE", $ManagedExternalProfile, "Process")

        $managedExternalServices = @("storage-service", "file-service", "push-service")
    }

    $requiredExternalUrls = @(
        "DEEP_STORAGE_URL",
        "DEEP_FILE_URL",
        "DEEP_PUSH_URL"
    )
    $missingExternalUrls = @(
        $requiredExternalUrls | Where-Object {
            [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_))
        }
    )

    if ($missingExternalUrls.Count -gt 0) {
        throw "BackendMode=external requires these environment variables: $($missingExternalUrls -join ', ')"
    }
}

try {
    if ($managedExternalServices.Count -gt 0) {
        $externalUpArguments = @("compose", "-f", $ComposeFile, "--profile", $ManagedExternalProfile, "up", "--build", "-d", "--wait") + $managedExternalServices
        Invoke-Docker -Arguments $externalUpArguments
    }

    $upArguments = @("compose", "-f", $ComposeFile, "up", "--build", "-d", "--wait") + $managedServices
    Invoke-Docker -Arguments $upArguments
    Invoke-Docker -Arguments @("compose", "-f", $ComposeFile, "--profile", "e2e", "run", "--rm", "--no-deps", "test-client")

    if ($Suite -eq "full" -and $BackendMode -eq "external" -and $managedExternalServices.Count -gt 0) {
        $hostArtifactDir = Join-Path $ArtifactDir "test-results"
        New-Item -ItemType Directory -Force $hostArtifactDir | Out-Null
        Repair-HostArtifactOwnership -Path $ArtifactDir
        [Environment]::SetEnvironmentVariable("DEEP_ARTIFACT_DIR", $hostArtifactDir, "Process")
        & node (Join-Path $ScriptDir "backend-external-restart-smoke.mjs")
        if ($LASTEXITCODE -ne 0) {
            throw "backend-external restart rehearsal failed with exit code $LASTEXITCODE"
        }
    }

    if ($RequirePushProviderCanary) {
        $hostArtifactDir = Join-Path $ArtifactDir "test-results"
        New-Item -ItemType Directory -Force $hostArtifactDir | Out-Null
        Repair-HostArtifactOwnership -Path $ArtifactDir
        [Environment]::SetEnvironmentVariable("DEEP_ARTIFACT_DIR", $hostArtifactDir, "Process")
        & node (Join-Path $ScriptDir "push-provider-canary.mjs")
        if ($LASTEXITCODE -ne 0) {
            throw "push provider canary failed with exit code $LASTEXITCODE"
        }
    }

    $SuiteCompletedSuccessfully = $true
}
catch {
    Repair-HostArtifactOwnership -Path $ArtifactDir
    & (Join-Path $ScriptDir "collect-artifacts.ps1") -ArtifactDir $ArtifactDir -ComposeFile $ComposeFile
    throw
}
finally {
    Repair-HostArtifactOwnership -Path $ArtifactDir
    & (Join-Path $ScriptDir "runtime-snapshot.ps1") -ArtifactDir $ArtifactDir

    if ($SuiteCompletedSuccessfully) {
        $snapshotPath = Join-Path $ArtifactDir "runtime.snapshot.json"
        if (-not (Test-Path $snapshotPath)) {
            throw "Runtime snapshot file was not generated: $snapshotPath"
        }

        $hardRequiredChecks = @(
            "router-health-ready",
            "registry-health-live",
            "staking-health-live",
            "contracts-devnet-chainid"
        )

        $softRequiredChecks = @(
            "registry-runtime",
            "staking-events-stats"
        )

        if ($BackendMode -eq "compat") {
            $softRequiredChecks += @(
                "storage-product-stats",
                "file-product-stats",
                "push-compat-stats",
                "calls-product-stats"
            )
        }
        else {
            $softRequiredChecks += @(
                "storage-external-stats",
                "file-external-stats",
                "push-external-stats"
            )
        }

        $snapshot = Get-Content -Raw $snapshotPath | ConvertFrom-Json
        $routerReadySnapshot = @($snapshot.snapshots | Where-Object { $_.name -eq "router-health-ready" } | Select-Object -First 1)
        $routerTransportMode = $null
        $routerTransportMocked = $false
        if ($null -ne $routerReadySnapshot -and
            $null -ne $routerReadySnapshot.body -and
            $routerReadySnapshot.body.PSObject.Properties.Name -contains "transportMode") {
            $routerTransportMode = [string]$routerReadySnapshot.body.transportMode
            $routerTransportMocked = $routerTransportMode -eq "mocked"
        }

        $gateWarnings = @()
        if ($routerTransportMocked) {
            $gateWarnings += "router-health-ready reported transportMode=mocked"
        }

        $failedHard = @($snapshot.snapshots | Where-Object {
                $hardRequiredChecks -contains $_.name -and -not $_.ok
            })

        $failedSoft = @($snapshot.snapshots | Where-Object {
                $softRequiredChecks -contains $_.name -and -not $_.ok
            })

        $pushProviderCanaryPath = Join-Path (Join-Path $ArtifactDir "test-results") "push-provider-canary.json"
        $pushProviderCanary = $null
        $pushProviderCanaryStatus = $null
        $pushProviderCanaryDelivered = $false
        if (Test-Path $pushProviderCanaryPath) {
            $pushProviderCanary = Get-Content -Raw $pushProviderCanaryPath | ConvertFrom-Json
            $pushProviderCanaryStatus = [string]$pushProviderCanary.status
            $pushProviderCanaryDelivered = $pushProviderCanary.status -eq "ok" -and
                $pushProviderCanary.provider.status -eq "delivered" -and
                $pushProviderCanary.provider.hasConfiguredUrl -eq $true
        }

        $gateSummary = [ordered]@{
            evaluatedAtUtc = [DateTimeOffset]::UtcNow.ToString("o")
            backendMode = $BackendMode
            hardRequiredChecks = $hardRequiredChecks
            softRequiredChecks = $softRequiredChecks
            failedHard = @($failedHard | ForEach-Object { $_.name })
            failedSoft = @($failedSoft | ForEach-Object { $_.name })
            requireRouterNoMock = [bool]$RequireRouterNoMock
            routerTransportMode = $routerTransportMode
            routerTransportMocked = $routerTransportMocked
            requirePushProviderCanary = [bool]$RequirePushProviderCanary
            pushProviderCanaryStatus = $pushProviderCanaryStatus
            pushProviderCanaryDelivered = $pushProviderCanaryDelivered
            warnings = $gateWarnings
        }
        $gateSummaryPath = Join-Path $ArtifactDir "runtime.gate.json"
        $gateSummary | ConvertTo-Json -Depth 10 | Out-File -Encoding utf8 $gateSummaryPath

        if ($routerTransportMocked) {
            $message = "Runtime gate detected mocked router transport. Set up a no-mock router profile before production sign-off."
            if ($RequireRouterNoMock) {
                throw $message
            }

            Write-Warning $message
        }

        if ($failedSoft.Count -gt 0) {
            $failedSoftNames = ($failedSoft | ForEach-Object { $_.name }) -join ", "
            Write-Warning "Runtime soft gate detected degraded checks: $failedSoftNames"
        }

        if ($failedHard.Count -gt 0) {
            $failedHardNames = ($failedHard | ForEach-Object { $_.name }) -join ", "
            throw "Runtime hard gate failed after successful suite. Failed checks: $failedHardNames"
        }

        if ($RequirePushProviderCanary) {
            if ($null -eq $pushProviderCanary) {
                throw "Push provider canary did not produce artifact: $pushProviderCanaryPath"
            }

            if (-not $pushProviderCanaryDelivered) {
                throw "Push provider canary artifact did not prove configured provider delivery: $pushProviderCanaryPath"
            }
        }

        if ($Suite -eq "full" -and $BackendMode -eq "external") {
            $loadArtifactDir = Join-Path $ArtifactDir "test-results"
            $loadArtifactPath = Join-Path $loadArtifactDir "backend-load-smoke.json"
            if (-not (Test-Path $loadArtifactPath)) {
                throw "BackendMode=external full suite did not produce load evidence artifact: $loadArtifactPath"
            }

            $loadArtifact = Get-Content -Raw $loadArtifactPath | ConvertFrom-Json
            if ($loadArtifact.backendMode -ne "external") {
                throw "Backend load evidence artifact is not tagged for external mode: $loadArtifactPath"
            }

            if ($null -eq $loadArtifact.statsDelta -or
                $loadArtifact.statsDelta.storage.storageStore -lt 1 -or
                $loadArtifact.statsDelta.file.fileUpload -lt 1 -or
                $loadArtifact.statsDelta.file.avatarUpload -lt 1 -or
                $loadArtifact.statsDelta.push.pushNotificationsQueued -lt 1) {
                throw "Backend load evidence artifact is missing expected storage/file/avatar/push activity deltas: $loadArtifactPath"
            }
            $loadArtifact | Add-Member -NotePropertyName generatedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString("o")) -Force
            $loadArtifact | ConvertTo-Json -Depth 40 | Out-File -Encoding utf8 $loadArtifactPath

            if ($managedExternalServices.Count -gt 0) {
                $restartArtifactPath = Join-Path $loadArtifactDir "backend-restart-smoke.json"
                if (-not (Test-Path $restartArtifactPath)) {
                    throw "Managed backend-external full suite did not produce restart rehearsal artifact: $restartArtifactPath"
                }

                $restartArtifact = Get-Content -Raw $restartArtifactPath | ConvertFrom-Json
                if ($restartArtifact.status -ne "ok") {
                    throw "Managed backend-external restart rehearsal artifact reported failure: $restartArtifactPath"
                }
                $restartArtifact | Add-Member -NotePropertyName generatedAt -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString("o")) -Force
                $restartArtifact | ConvertTo-Json -Depth 40 | Out-File -Encoding utf8 $restartArtifactPath
            }
        }
    }

    if ($managedExternalServices.Count -gt 0) {
        Invoke-Docker -Arguments @("compose", "-f", $ComposeFile, "--profile", $ManagedExternalProfile, "down", "--volumes", "--remove-orphans") -AllowFailure
        if ($script:LastDockerExitCode -ne 0) {
            Write-Warning "docker compose cleanup for managed external profile failed with exit code $script:LastDockerExitCode"
        }
    }

    Invoke-Docker -Arguments @("compose", "-f", $ComposeFile, "down", "--volumes", "--remove-orphans") -AllowFailure
    if ($script:LastDockerExitCode -ne 0) {
        Write-Warning "docker compose cleanup failed with exit code $script:LastDockerExitCode"
    }
    Clear-DeepEphemeralComposeSecrets -GeneratedNames $generatedComposeSecretNames
}
