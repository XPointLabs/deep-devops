[CmdletBinding()]
param(
    [string]$BindHost = '192.168.1.44',
    [string]$EvidencePath,
    [ValidateRange(5, 300)][int]$TtlSeconds = 120
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$Launcher = Join-Path $PSScriptRoot 'survival-dev.ps1'
$PinnedXNode = Join-Path $Root 'artifacts\survival-dev\build-contexts\xnode'
$DriverSource = Join-Path $Root 'tools\survival-mailbox-driver'
$BuildHelper = Join-Path $PSScriptRoot 'survival-dev-mailbox-build-inputs.ps1'
$ExpectedBuildHelperSha256 = '04c0f2cf9118b648ce4868390451afd33cd6ad9ce550703b24b3f429ce694b2c'
$ExpectedXNodeCommit = '4d05fe7dd2dadd3f094c172a382ad675d2ff545a'
$ExpectedXNodeManifestSha256 = '2b2a223c96bb3a9cb075262e14b64e083d28f3a2b4a1068b68c737250311e52a'
$ExpectedDriverSha256 = @{
    'MailboxGrantProvisioner.cs' = '4028b9c7388530c0a8071bae715d717b755d5fe5645e229ef9d205e81d8e258a'
    'MailboxRuntimePublisher.cs' = 'd6aad71f65987f620ccf0d5a06394240aa199d3bb92ef38b81a9594f8e9ff94b'
    'Program.cs' = 'c63e30740a455416a52f5d208c5d3b019abca5ae13c1b8830f63164e82db2766'
    'SurvivalMailboxDriver.csproj' = '4db436d69ea88ac3ff16f08c161b61cc0c048bad84cb7e529b2208fa569eafbe'
}
$PublicAuthority = Join-Path $Root 'artifacts\survival-dev\mailbox-peer-authority.public.json'
$Secrets = Join-Path $Root '.secrets\survival-dev'
$State = Join-Path $Root 'artifacts\survival-dev\resend-chaos-driver-state'
$BuildWork = Join-Path ([IO.Path]::GetTempPath()) ('deep-resend-chaos-driver-' + [Guid]::NewGuid().ToString('N'))
$SourceRoot = Join-Path $BuildWork 'source'
$VerificationRoot = Join-Path $BuildWork 'verification'
$BuildArtifacts = Join-Path $BuildWork 'artifacts'
$PublishRoot = Join-Path $BuildWork 'publish'
$DriverDll = Join-Path $PublishRoot 'SurvivalMailboxDriver.dll'
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\resend-chaos-integration.json'
}
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$artifactsPrefix = ([IO.Path]::GetFullPath((Join-Path $Root 'artifacts'))).TrimEnd('\') + '\'
if (-not $EvidencePath.StartsWith($artifactsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resend chaos evidence path must remain inside the artifacts directory.'
}
Remove-Item -LiteralPath $EvidencePath -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $State -Recurse -Force -ErrorAction SilentlyContinue

$helperBytes = [IO.File]::ReadAllBytes($BuildHelper)
try {
    $helperHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actualBuildHelperSha256 = ([BitConverter]::ToString(
            $helperHasher.ComputeHash($helperBytes)).Replace('-', '')).ToLowerInvariant()
    } finally {
        $helperHasher.Dispose()
    }
    if ($helperBytes.Length -gt 1024 * 1024 -or
        $actualBuildHelperSha256 -cne $ExpectedBuildHelperSha256) {
        throw 'The immutable mailbox build helper does not match its exact reviewed pin.'
    }
    . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($helperBytes)))
} finally {
    [Array]::Clear($helperBytes, 0, $helperBytes.Length)
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    $output = @(& $File @Arguments)
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
    return $output
}

function Get-RunningStackCount() {
    return @(& docker ps --filter 'label=com.docker.compose.project=deep-survival-dev' --format '{{.Names}}').Count
}

function Get-ReceiverTotals() {
    $stored = 0L
    $duplicates = 0L
    # xnode-1's public publisher is deliberately removed while chaos is active;
    # only the five remote peer receivers are relevant to fanout duplication.
    foreach ($index in 2..6) {
        $status = Invoke-RestMethod -Uri "http://${BindHost}:$((41800 + $index))/status" -TimeoutSec 5
        $stored += [long]$status.mailbox.receiver.stored
        $duplicates += [long]$status.mailbox.receiver.duplicates
    }
    return [pscustomobject]@{ stored = $stored; duplicates = $duplicates }
}

if ((Get-RunningStackCount) -ne 14) { throw 'Resend chaos integration requires the ordinary 14-container survival stack.' }
$initial = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $Launcher -Action ChaosStatus)
$initialStatus = ($initial | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v1"' } | Select-Object -Last 1) | ConvertFrom-Json
if ($initialStatus.running -ne $false -or $initialStatus.armed -ne $false) { throw 'Resend chaos must start fully off.' }

$chaosStarted = $false
$sourceLocks = $null
try {
    [void](Invoke-Checked node @('--test', '--test-force-exit', (Join-Path $Root 'tools\survival-resend-chaos\resend-chaos-proxy.test.mjs')))
    [void][IO.Directory]::CreateDirectory($BuildWork)
    Set-MailboxDirectoryExclusiveWritable $BuildWork
    $isolated = New-SurvivalMailboxIsolatedSource `
        -XNodeSource $PinnedXNode `
        -DriverSource $DriverSource `
        -Destination $SourceRoot `
        -ExpectedCommit $ExpectedXNodeCommit `
        -ExpectedManifestSha256 $ExpectedXNodeManifestSha256 `
        -ExpectedDriverSha256 $ExpectedDriverSha256
    Set-MailboxTreeReadOnly $SourceRoot
    $sourceLocks = Open-MailboxTreeReadLocks $SourceRoot
    Assert-SurvivalMailboxIsolatedSource $isolated
    [void](Invoke-Checked dotnet @(
        'publish', $isolated.DriverProject,
        '--configuration', 'Release',
        '--output', $PublishRoot,
        '--artifacts-path', $BuildArtifacts,
        '--no-self-contained',
        '-p:UseAppHost=false',
        "-p:XNodeSource=$($isolated.XNode)",
        '-p:ImportDirectoryBuildProps=false',
        '-p:ImportDirectoryBuildTargets=false',
        "-p:DirectoryPackagesPropsPath=$(Join-Path $isolated.XNode 'Directory.Packages.props')"))
    if (-not (Test-Path -LiteralPath $DriverDll -PathType Leaf)) {
        throw 'The isolated mailbox driver publish did not produce its exact entry assembly.'
    }
    Assert-SurvivalMailboxIsolatedSource $isolated

    # Re-read and copy the original pinned inventory after the build. This is
    # the final source authority immediately before ChaosBegin can invoke Docker.
    $verified = New-SurvivalMailboxIsolatedSource `
        -XNodeSource $PinnedXNode `
        -DriverSource $DriverSource `
        -Destination $VerificationRoot `
        -ExpectedCommit $ExpectedXNodeCommit `
        -ExpectedManifestSha256 $ExpectedXNodeManifestSha256 `
        -ExpectedDriverSha256 $ExpectedDriverSha256
    Assert-SurvivalMailboxIsolatedSource $verified
    Set-MailboxTreeWritable $VerificationRoot
    Remove-Item -LiteralPath $VerificationRoot -Recurse -Force

    [void](Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosBegin', '-LanHost', $BindHost, '-ChaosTtlSeconds', [string]$TtlSeconds))
    $chaosStarted = $true
    # ChaosBegin intentionally recreates the XNodes, which resets process-local
    # counters; take the comparison baseline only after that supported lifecycle.
    $before = Get-ReceiverTotals
    $runId = [Guid]::NewGuid().ToString('N')
    $driverOutput = Invoke-Checked dotnet @(
        $DriverDll, 'client-uncertain-resend',
        '--secrets-dir', $Secrets,
        '--state-dir', $State,
        '--authority-public', $PublicAuthority,
        '--coordinator-url', "http://${BindHost}:41801",
        '--client-url', "http://${BindHost}:41801",
        '--require-non-loopback-coordinator',
        '--run-id', $runId)
    $driver = ($driverOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-uncertain-resend"' } | Select-Object -Last 1) | ConvertFrom-Json
    if ($driver.passed -ne $true -or $driver.details.serverItemCount -ne 1 -or
        $driver.details.duplicateServerItemCreated -ne $false -or
        $driver.details.exactReplay -ne $true -or $driver.details.nativeMqr3 -ne $true) {
        throw 'Real uncertain-resend driver assertions failed.'
    }
    $statusOutput = Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosStatus')
    $chaos = ($statusOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v1"' } | Select-Object -Last 1) | ConvertFrom-Json
    if ($chaos.armed -ne $false -or $chaos.consumed -ne $true -or
        $chaos.upstreamSuccessObserved -ne 4 -or $chaos.downstreamDropped -ne 1 -or
        $chaos.requestCount -ne 4 -or $chaos.identifiersIncluded -ne $false -or
        $chaos.payloadInspected -ne $false) {
        throw 'One-shot chaos counters did not prove one exact post-durable drop.'
    }
    $after = Get-ReceiverTotals
    if (($after.stored - $before.stored) -ne 1 -or ($after.duplicates - $before.duplicates) -ne 0) {
        throw 'Real XNode receiver counters did not prove one new replica and zero duplicate writes.'
    }
}
finally {
    try {
        if ($chaosStarted) {
            [void](Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosEnd'))
        }
    } finally {
        Remove-Item -LiteralPath $State -Recurse -Force -ErrorAction SilentlyContinue
        if ($null -ne $sourceLocks) {
            foreach ($sourceLock in $sourceLocks) { $sourceLock.Dispose() }
        }
        foreach ($temporaryRoot in @($VerificationRoot, $SourceRoot)) {
            if (Test-Path -LiteralPath $temporaryRoot) {
                Set-MailboxTreeWritable $temporaryRoot
            }
        }
        Remove-Item -LiteralPath $BuildWork -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ((Get-RunningStackCount) -ne 14) { throw 'Ordinary survival stack was not fully restored.' }
$proxyCount = @(& docker ps --filter 'label=com.xpoint.survival.resend-chaos=development-only' --format '{{.Names}}').Count
$tokenExists = Test-Path -LiteralPath (Join-Path $Secrets 'resend-chaos.token')
if ($proxyCount -ne 0 -or $tokenExists) { throw 'Chaos cleanup did not remove the proxy and protected token.' }

$evidence = [pscustomobject]@{
    schema = 'deep-survival-resend-chaos-evidence.v1'
    generatedAt = [DateTimeOffset]::UtcNow
    scope = 'development-only-real-mau2-ingress'
    passed = $true
    assertions = [pscustomobject]@{
        deterministicProxyContract = $true
        realXNodeDurableBeforeDrop = $true
        exactlyOneDownstreamDrop = $true
        exactRetryReturnsNativeMqr3 = $true
        exactReplayStable = $true
        serverItemCount = 1
        remoteReplicaStoredDelta = 1
        remoteDuplicateDelta = 0
        payloadInspected = $false
        identifiersIncluded = $false
        ttlAndRestartDefaultDisarmed = $true
        ordinaryStackRestored = $true
        protectedTokenDeleted = $true
    }
    counters = [pscustomobject]@{
        upstreamSuccessObserved = 4
        downstreamDropped = 1
        requestCount = 4
    }
    limitations = 'DEV-only fault injection with a software-held random lab token; it is structurally absent from staging and production Compose.'
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
[IO.File]::WriteAllText($EvidencePath, (($evidence | ConvertTo-Json -Depth 6) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "Resend chaos integration evidence: $EvidencePath"
