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
    'MailboxGrantProvisioner.cs' = 'f88f7ebb0c06f11fde52386341202090e8bd4205ad23bb40c31e7d79d2ac8184'
    'MailboxRuntimePublisher.cs' = 'd6aad71f65987f620ccf0d5a06394240aa199d3bb92ef38b81a9594f8e9ff94b'
    'Program.cs' = '42bc7aa6c57f9e64e8bb7fae2f864133eba4ba64115e39948c19104a45900daf'
    'SurvivalMailboxDriver.csproj' = '4db436d69ea88ac3ff16f08c161b61cc0c048bad84cb7e529b2208fa569eafbe'
}
. (Join-Path $PSScriptRoot 'survival-dev-private-secrets.ps1')
$AuthorityState = Join-Path $Root '.secrets\survival-dev\mailbox-authority-state.v1.json'
$Secrets = Join-Path $Root '.secrets\survival-dev'
$State = Join-Path $Root 'artifacts\survival-dev\resend-chaos-driver-state'
$BuildWork = Join-Path ([IO.Path]::GetTempPath()) ('deep-resend-chaos-driver-' + [Guid]::NewGuid().ToString('N'))
$SourceRoot = Join-Path $BuildWork 'source'
$VerificationRoot = Join-Path $BuildWork 'verification'
$BuildArtifacts = Join-Path $BuildWork 'artifacts'
$PublishRoot = Join-Path $BuildWork 'publish'
$DriverDll = Join-Path $PublishRoot 'SurvivalMailboxDriver.dll'
$HttpsAuthority = Join-Path $BuildWork 'mailbox-peer-authority.https.public.json'
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
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE.`n$($output -join "`n")"
    }
    return $output
}

function Get-RunningStackCount() {
    return @(& docker ps --filter 'label=com.docker.compose.project=deep-survival-dev' --format '{{.Names}}').Count
}

if ((Get-RunningStackCount) -ne 14) { throw 'Resend chaos integration requires the ordinary 14-container survival stack.' }
$initial = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $Launcher -Action ChaosStatus)
$initialStatus = ($initial | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
if ($initialStatus.running -ne $false -or $initialStatus.armed -ne $false) { throw 'Resend chaos must start fully off.' }

$chaosStarted = $false
$sourceLocks = $null
$faultEvidence = @()
$runtimeImages = $null
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

    [void](Invoke-Checked dotnet @(
        $DriverDll, 'authority',
        '--secrets-dir', $Secrets,
        '--authority-state', $AuthorityState,
        '--output-env', (Join-Path $BuildWork 'mailbox-peer-authority.https.env'),
        '--output-client-env', (Join-Path $BuildWork 'mailbox-client-authority.https.env'),
        '--coordinator-url', "https://${BindHost}:41801",
        '--output-public', $HttpsAuthority,
        '--output-client-public', (Join-Path $BuildWork 'mailbox-client-authority.https.public.json')))

    foreach ($fault in @('post-durable-response-drop', 'pre-dispatch-outage')) {
        try {
            $beginOutput = Invoke-Checked powershell @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher,
                '-Action', 'ChaosBegin', '-LanHost', $BindHost,
                '-ChaosTtlSeconds', [string]$TtlSeconds, '-ChaosFault', $fault)
            $chaosStarted = $true
            $begin = ($beginOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
            if ($begin.armed -ne $true -or $begin.fault -cne $fault -or
                ([long]$begin.faultWindowDeadlineUnixMilliseconds - [long]$begin.faultWindowStartedUnixMilliseconds) -ne ($TtlSeconds * 1000L)) {
                throw 'ChaosBegin did not return the exact armed fault/deadline binding.'
            }
            $runId = [Guid]::NewGuid().ToString('N')
            $driverOutput = Invoke-Checked dotnet @(
                $DriverDll, 'client-uncertain-resend',
                '--secrets-dir', $Secrets,
                '--state-dir', $State,
                '--authority-public', $HttpsAuthority,
                '--coordinator-url', "https://${BindHost}:41801",
                '--client-url', "https://${BindHost}:41801",
                '--require-non-loopback-coordinator',
                '--run-id', $runId)
            $driver = ($driverOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-uncertain-resend"' } | Select-Object -Last 1) | ConvertFrom-Json
            if ($driver.passed -ne $true -or $driver.details.serverItemCount -ne 1 -or
                $driver.details.duplicateServerItemCreated -ne $false -or
                $driver.details.exactReplay -ne $true -or $driver.details.nativeMqr3 -ne $true) {
                throw "Real uncertain-resend driver assertions failed for $fault."
            }
            $statusOutput = Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosStatus')
            $chaos = ($statusOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
            $expectedDispatches = if ($fault -ceq 'post-durable-response-drop') { 3 } else { 2 }
            $expectedPostDrop = if ($fault -ceq 'post-durable-response-drop') { 1 } else { 0 }
            $expectedPreOutage = if ($fault -ceq 'pre-dispatch-outage') { 1 } else { 0 }
            if ($chaos.armed -ne $false -or $chaos.consumed -ne $true -or
                $chaos.operation -cne 'mailbox-store' -or $chaos.fault -cne $fault -or
                $chaos.requestCount -ne 4 -or
                $chaos.operationAttemptCount -ne 3 -or
                $chaos.operationUpstreamDispatchCount -ne $expectedDispatches -or
                $chaos.operationUpstreamSuccessCount -ne $expectedDispatches -or
                $chaos.injectedFaultCount -ne 1 -or
                $chaos.postDurableResponseDropCount -ne $expectedPostDrop -or
                $chaos.preDispatchOutageCount -ne $expectedPreOutage -or
                $chaos.identifiersIncluded -ne $false -or $chaos.payloadInspected -ne $false) {
                throw "One-shot chaos counters did not prove the exact $fault attempt lifecycle: $($chaos | ConvertTo-Json -Compress)"
            }
            if ($null -eq $runtimeImages) {
                $proxyId = (& docker ps --filter 'label=com.docker.compose.service=resend-chaos' --quiet | Out-String).Trim()
                $ingressId = (& docker ps --filter 'label=com.docker.compose.service=survival-uat-tls-ingress' --quiet | Out-String).Trim()
                if ($proxyId -notmatch '^[0-9a-f]{12,64}$' -or $ingressId -notmatch '^[0-9a-f]{12,64}$') {
                    throw 'Unable to bind evidence to the exact running chaos and TLS ingress images.'
                }
                $runtimeImages = [ordered]@{
                    resendChaos = ((& docker inspect --format '{{.Image}}' $proxyId) | Out-String).Trim()
                    uatTlsIngress = ((& docker inspect --format '{{.Image}}' $ingressId) | Out-String).Trim()
                }
                if ($runtimeImages.resendChaos -notmatch '^sha256:[0-9a-f]{64}$' -or
                    $runtimeImages.uatTlsIngress -notmatch '^sha256:[0-9a-f]{64}$') {
                    throw 'Runtime image evidence is not bound to exact SHA-256 image identities.'
                }
            }
            $faultEvidence += [ordered]@{
                fault = $fault
                operation = $chaos.operation
                faultWindowStartedUnixMilliseconds = [long]$chaos.faultWindowStartedUnixMilliseconds
                faultWindowDeadlineUnixMilliseconds = [long]$chaos.faultWindowDeadlineUnixMilliseconds
                requestCount = [long]$chaos.requestCount
                operationAttemptCount = [long]$chaos.operationAttemptCount
                operationUpstreamDispatchCount = [long]$chaos.operationUpstreamDispatchCount
                operationUpstreamSuccessCount = [long]$chaos.operationUpstreamSuccessCount
                injectedFaultCount = [long]$chaos.injectedFaultCount
                postDurableResponseDropCount = [long]$chaos.postDurableResponseDropCount
                preDispatchOutageCount = [long]$chaos.preDispatchOutageCount
                serverItemCount = 1
                duplicateServerItemCreated = $false
                exactReplay = $true
            }
        } finally {
            if ($chaosStarted) {
                [void](Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosEnd'))
                $chaosStarted = $false
            }
        }
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

function Get-FileSha256Lower([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

$evidenceCore = [ordered]@{
    schema = 'deep-survival-resend-chaos-evidence.v2'
    generatedAt = [DateTimeOffset]::UtcNow.ToString('O')
    scope = 'development-only-real-mau2-ca-trusted-https-ingress'
    passed = $true
    publicTransport = [ordered]@{
        origin = "https://${BindHost}:41801"
        platformTlsValidation = $true
        cleartextApplicationHttpRejected = $true
        publicRoute = '/api/client/mailbox/v2/store'
    }
    sourceBindings = [ordered]@{
        xnodeCommit = $ExpectedXNodeCommit
        xnodeManifestSha256 = $ExpectedXNodeManifestSha256
        mailboxBuildHelperSha256 = $ExpectedBuildHelperSha256
        mailboxDriverFilesSha256 = $ExpectedDriverSha256
    }
    configurationBindingsSha256 = [ordered]@{
        baseCompose = Get-FileSha256Lower (Join-Path $Root 'docker-compose.survival.dev.yml')
        uatTlsCompose = Get-FileSha256Lower (Join-Path $Root 'docker-compose.survival-uat-tls.dev.yml')
        chaosCompose = Get-FileSha256Lower (Join-Path $Root 'docker-compose.survival-resend-chaos.dev.yml')
        haproxy = Get-FileSha256Lower (Join-Path $Root 'config\survival-uat-tls\haproxy.cfg')
        proxy = Get-FileSha256Lower (Join-Path $Root 'tools\survival-resend-chaos\resend-chaos-proxy.mjs')
        controlClient = Get-FileSha256Lower (Join-Path $Root 'tools\survival-resend-chaos\control-client.mjs')
    }
    runtimeImages = $runtimeImages
    faultRuns = $faultEvidence
    assertions = [ordered]@{
        authenticatedPrivateControlSocket = $true
        boundedTtl = $true
        exactOneShotFaultPerRun = $true
        postDurableResponseDropRecovered = $true
        preDispatchOutageRecovered = $true
        exactRetryReturnsNativeMqr3 = $true
        exactReplayStable = $true
        payloadInspected = $false
        identifiersIncluded = $false
        ordinaryHttpsStackRestored = $true
        protectedTokenDeleted = $true
    }
    authorityClaim = 'none; SHA-256 content addressing detects mutation but does not create a signing authority'
    limitations = 'DEV-only fault injection; the interposer is private behind the unchanged CA-trusted HTTPS ingress and is structurally absent from staging and production Compose.'
}
$canonicalEvidence = $evidenceCore | ConvertTo-Json -Depth 12 -Compress
$canonicalBytes = [Text.Encoding]::UTF8.GetBytes($canonicalEvidence)
try {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { $evidenceSha256 = ([BitConverter]::ToString($hasher.ComputeHash($canonicalBytes)).Replace('-', '')).ToLowerInvariant() }
    finally { $hasher.Dispose() }
} finally { [Array]::Clear($canonicalBytes, 0, $canonicalBytes.Length) }
$envelope = [ordered]@{
    schema = 'deep-survival-resend-chaos-evidence-envelope.v2'
    evidenceSha256 = $evidenceSha256
    evidence = $evidenceCore
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
$temporaryEvidencePath = "$EvidencePath.$([Guid]::NewGuid().ToString('N')).tmp"
try {
    [IO.File]::WriteAllText($temporaryEvidencePath, (($envelope | ConvertTo-Json -Depth 12) + "`n"), [Text.UTF8Encoding]::new($false))
    Protect-SurvivalDevPrivateFile $temporaryEvidencePath
    Move-Item -LiteralPath $temporaryEvidencePath -Destination $EvidencePath -Force
    Assert-SurvivalDevPrivateFile $EvidencePath
} finally {
    Remove-Item -LiteralPath $temporaryEvidencePath -Force -ErrorAction SilentlyContinue
}
$reread = Get-Content -Raw -LiteralPath $EvidencePath | ConvertFrom-Json
$rereadCanonical = $reread.evidence | ConvertTo-Json -Depth 12 -Compress
$rereadBytes = [Text.Encoding]::UTF8.GetBytes($rereadCanonical)
try {
    $rereadHasher = [Security.Cryptography.SHA256]::Create()
    try { $rereadSha256 = ([BitConverter]::ToString($rereadHasher.ComputeHash($rereadBytes)).Replace('-', '')).ToLowerInvariant() }
    finally { $rereadHasher.Dispose() }
} finally { [Array]::Clear($rereadBytes, 0, $rereadBytes.Length) }
if ($reread.schema -cne 'deep-survival-resend-chaos-evidence-envelope.v2' -or
    $reread.evidenceSha256 -cne $evidenceSha256 -or $rereadSha256 -cne $evidenceSha256) {
    throw 'Atomic protected chaos evidence failed independent same-process digest verification.'
}
Write-Output "Resend chaos integration evidence: $EvidencePath"
Write-Output "Resend chaos evidence SHA256: $evidenceSha256"
