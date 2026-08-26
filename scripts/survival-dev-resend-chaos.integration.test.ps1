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
$ExpectedBuildHelperSha256 = 'c5e0f08e0816296734195a27b2c8a47a207b0f1ade88f0186caffe02334f1456'
$ExpectedXNodeCommit = 'c8b38e2b5221fa6c047717202a50a80ebd4f2dd6'
$ExpectedXNodeManifestSha256 = '0d9ad51d967681816e816f7177c565a770143dfc9983cd9746fdf2cf20096ce6'
$ExpectedDriverSha256 = @{
    'MailboxGrantProvisioner.cs' = 'f88f7ebb0c06f11fde52386341202090e8bd4205ad23bb40c31e7d79d2ac8184'
    'MailboxRuntimePublisher.cs' = 'aa725b67ddfd48193a3e5cc3f39f529130e589e05fa14b1569123c8a8cf42866'
    'PrivateCrossProcessState.cs' = '651d8256822d41b9a7bceab1e6d6bb45740026cac00f487a564befe7777f272b'
    'Program.cs' = '9f18d7cfbfbb12de01a2787cf98f526131907140a789516e9a2cffb0e3ef073c'
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
if (Test-Path -LiteralPath $EvidencePath) {
    Remove-Item -LiteralPath $EvidencePath -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $EvidencePath) {
    throw 'Stale resend chaos evidence survived terminating initial cleanup.'
}

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
Remove-MailboxPrivateStateDirectory `
    -Path $State `
    -ExpectedParent (Join-Path $Root 'artifacts\survival-dev')
if (Test-Path -LiteralPath $State) {
    throw 'Stale private ACK state survived terminating initial cleanup.'
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    $output = @(& $File @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE.`n$($output -join "`n")"
    }
    return $output
}

function Assert-OrdinaryStack() {
    $expected = @(
        'file', 'push', 'registry', 'storage', 'survival-uat-crl',
        'survival-uat-tls-ingress', 'turn',
        'xnode-1', 'xnode-2', 'xnode-3', 'xnode-4', 'xnode-5', 'xnode-6'
    ) | Sort-Object
    $rows = @(& docker ps `
        --filter 'label=com.docker.compose.project=deep-survival-dev' `
        --format json)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the ordinary survival service topology.'
    }
    $actual = @($rows | ForEach-Object {
        $labels = ([string]($_ | ConvertFrom-Json).Labels)
        $match = [regex]::Match($labels, '(?:^|,)com\.docker\.compose\.service=([^,]+)')
        if (-not $match.Success) { throw 'A survival container has no Compose service label.' }
        $match.Groups[1].Value
    }) | Sort-Object
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw 'Resend chaos integration requires the exact ordinary survival service topology.'
    }
}

Assert-OrdinaryStack
$initial = @(& powershell -NoProfile -ExecutionPolicy Bypass -File $Launcher -Action ChaosStatus)
$initialStatus = ($initial | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
if ($initialStatus.running -ne $false -or $initialStatus.armed -ne $false) { throw 'Resend chaos must start fully off.' }

$chaosStarted = $false
$sourceLocks = $null
$faultEvidence = @()
$runtimeImages = $null
$runFailure = $null
try {
    [void](Invoke-Checked node @('--test', '--test-force-exit', (Join-Path $Root 'tools\survival-resend-chaos\resend-chaos-proxy.test.mjs')))
    [void][IO.Directory]::CreateDirectory($State)
    Set-MailboxDirectoryExclusiveWritable $State
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
        '--output-client-public', (Join-Path $BuildWork 'mailbox-client-authority.https.public.json'),
        '--output-privacy-routes-android', (Join-Path $BuildWork 'privacy-routes.android.v1.json'),
        '--output-privacy-routes-windows', (Join-Path $BuildWork 'privacy-routes.windows.v1.json'),
        '--privacy-entry-host', $BindHost))

    foreach ($fault in @('post-durable-response-drop', 'pre-dispatch-outage', 'post-durable-ack-response-drop')) {
        try {
            $runId = [Guid]::NewGuid().ToString('N')
            $commonDriverArguments = @(
                '--secrets-dir', $Secrets,
                '--state-dir', $State,
                '--authority-public', $HttpsAuthority,
                '--coordinator-url', "https://${BindHost}:41801",
                '--client-url', "https://${BindHost}:41801",
                '--privacy-routes', (Join-Path $BuildWork 'privacy-routes.android.v1.json'),
                '--require-non-loopback-coordinator')
            if ($fault -ceq 'post-durable-ack-response-drop') {
                # MAU2 is opaque at public ingress, so prepare Store/Retrieve before
                # arming the one-shot fault and expose only the ACK to that window.
                $prepareArguments = @($DriverDll, 'client-prepare-ack-loss') +
                    $commonDriverArguments + @('--run-id', $runId)
                $prepareOutput = Invoke-Checked dotnet $prepareArguments
                $prepare = ($prepareOutput | Where-Object {
                    $_ -match '^\{"schemaVersion":1,"phase":"client-prepare-ack-loss"'
                } | Select-Object -Last 1) | ConvertFrom-Json
                if ($prepare.passed -ne $true -or
                    $prepare.details.retrievedItemsBeforeAck -ne 1 -or
                    $prepare.details.prepared -ne $true -or
                    $prepare.details.ackDispatched -ne $false) {
                    throw 'Real ACK loss preparation did not persist one exact pending ACK.'
                }
            }
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
            $preRestartCounters = $null
            $postRestartCounters = $null
            $driverAssertions = $null
            if ($fault -ceq 'post-durable-ack-response-drop') {
                $lossArguments = @($DriverDll, 'client-ack-loss') + $commonDriverArguments + @('--run-id', $runId)
                $lossOutput = Invoke-Checked dotnet $lossArguments
                $loss = ($lossOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-ack-loss"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($loss.passed -ne $true -or $loss.details.processRestartRequired -ne $true -or
                    $loss.details.retrievedItemsBeforeAck -ne 1) {
                    throw 'Real ACK loss driver did not stop at the exact crash window.'
                }
                $preRestartOutput = Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosStatus')
                $preRestart = ($preRestartOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($preRestart.operation -cne 'mailbox-ack' -or $preRestart.fault -cne $fault -or
                    $preRestart.requestCount -ne 1 -or $preRestart.operationAttemptCount -ne 1 -or
                    $preRestart.operationUpstreamDispatchCount -ne 1 -or
                    $preRestart.operationUpstreamSuccessCount -ne 1 -or
                    $preRestart.injectedFaultCount -ne 1 -or
                    $preRestart.postDurableAckResponseDropCount -ne 1) {
                    throw "ACK crash-window counters were not exact before process restart: $($preRestart | ConvertTo-Json -Compress)"
                }
                $preRestartCounters = [ordered]@{
                    requestCount = 1
                    operationAttemptCount = 1
                    operationUpstreamDispatchCount = 1
                    operationUpstreamSuccessCount = 1
                    injectedFaultCount = 1
                }
                $retryArguments = @($DriverDll, 'client-retry-ack-loss') + $commonDriverArguments
                $retryOutput = Invoke-Checked dotnet $retryArguments
                $retry = ($retryOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-retry-ack-loss"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($retry.passed -ne $true -or $retry.details.processRestarted -ne $true -or
                    $retry.details.nativeMar1 -ne $true -or
                    $retry.details.tombstoneQuorums -ne 1 -or $retry.details.retrieveAfterAckItems -ne 0) {
                    throw 'Real ACK retry after process restart did not prove durable ACK and empty inbox.'
                }
                $postRestartOutput = Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosStatus')
                $postRestart = ($postRestartOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($postRestart.requestCount -ne 3 -or $postRestart.operationAttemptCount -ne 3 -or
                    $postRestart.operationUpstreamDispatchCount -ne 3 -or
                    $postRestart.operationUpstreamSuccessCount -ne 3 -or
                    $postRestart.injectedFaultCount -ne 1 -or
                    $postRestart.postDurableAckResponseDropCount -ne 1) {
                    throw "ACK counters were not exact after process restart and one retry: $($postRestart | ConvertTo-Json -Compress)"
                }
                $postRestartCounters = [ordered]@{
                    requestCount = 3
                    operationAttemptCount = 3
                    operationUpstreamDispatchCount = 3
                    operationUpstreamSuccessCount = 3
                    injectedFaultCount = 1
                }
                $replayArguments = @($DriverDll, 'client-replay-ack-loss') + $commonDriverArguments
                $replayOutput = Invoke-Checked dotnet $replayArguments
                $replay = ($replayOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-replay-ack-loss"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($replay.passed -ne $true -or $replay.details.exactReplay -ne $true -or
                    $replay.details.nativeMar1 -ne $true) {
                    throw 'Exact ACK replay after recovery changed the native MAR1.'
                }
                $driverAssertions = [ordered]@{
                    processRestarted = $true
                    exactAckReplay = $true
                    nativeMar1 = $true
                    tombstoneQuorums = 1
                    retrieveAfterAckItems = 0
                }
            } else {
                $driverArguments = @($DriverDll, 'client-uncertain-resend') + $commonDriverArguments + @('--run-id', $runId)
                $driverOutput = Invoke-Checked dotnet $driverArguments
                $driver = ($driverOutput | Where-Object { $_ -match '^\{"schemaVersion":1,"phase":"client-uncertain-resend"' } | Select-Object -Last 1) | ConvertFrom-Json
                if ($driver.passed -ne $true -or $driver.details.serverItemCount -ne 1 -or
                    $driver.details.duplicateServerItemCreated -ne $false -or
                    $driver.details.exactReplay -ne $true -or $driver.details.nativeMqr3 -ne $true) {
                    throw "Real uncertain-resend driver assertions failed for $fault."
                }
                $driverAssertions = [ordered]@{
                    serverItemCount = 1
                    duplicateServerItemCreated = $false
                    exactStoreReplay = $true
                    nativeMqr3 = $true
                }
            }
            $statusOutput = Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosStatus')
            $chaos = ($statusOutput | Where-Object { $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"' } | Select-Object -Last 1) | ConvertFrom-Json
            $ackFault = $fault -ceq 'post-durable-ack-response-drop'
            $expectedOperation = if ($ackFault) { 'mailbox-ack' } else { 'mailbox-store' }
            $expectedRequests = 4
            $expectedDispatches = if ($fault -ceq 'pre-dispatch-outage') { 3 } else { 4 }
            $expectedPostDrop = if ($fault -ceq 'post-durable-response-drop') { 1 } else { 0 }
            $expectedAckDrop = if ($ackFault) { 1 } else { 0 }
            $expectedPreOutage = if ($fault -ceq 'pre-dispatch-outage') { 1 } else { 0 }
            if ($chaos.armed -ne $false -or $chaos.consumed -ne $true -or
                $chaos.operation -cne $expectedOperation -or $chaos.fault -cne $fault -or
                $chaos.requestCount -ne $expectedRequests -or
                $chaos.operationAttemptCount -ne 4 -or
                $chaos.operationUpstreamDispatchCount -ne $expectedDispatches -or
                $chaos.operationUpstreamSuccessCount -ne $expectedDispatches -or
                $chaos.injectedFaultCount -ne 1 -or
                $chaos.postDurableResponseDropCount -ne $expectedPostDrop -or
                $chaos.postDurableAckResponseDropCount -ne $expectedAckDrop -or
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
                postDurableAckResponseDropCount = [long]$chaos.postDurableAckResponseDropCount
                preDispatchOutageCount = [long]$chaos.preDispatchOutageCount
                preRestartCounters = $preRestartCounters
                postRestartCounters = $postRestartCounters
                outcome = $driverAssertions
            }
        } catch {
            $faultFailure = $_.Exception
            try {
                $failureStatusOutput = Invoke-Checked powershell @(
                    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher,
                    '-Action', 'ChaosStatus')
                $failureStatus = ($failureStatusOutput | Where-Object {
                        $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"'
                    } | Select-Object -Last 1) | ConvertFrom-Json
                throw [InvalidOperationException]::new(
                    ('Fault {0} failed with sanitized proxy counters: requests={1}, attempts={2}, dispatches={3}, successes={4}, injections={5}.' -f
                        $fault,
                        $failureStatus.requestCount,
                        $failureStatus.operationAttemptCount,
                        $failureStatus.operationUpstreamDispatchCount,
                        $failureStatus.operationUpstreamSuccessCount,
                        $failureStatus.injectedFaultCount),
                    $faultFailure)
            } catch {
                if ($_.Exception.InnerException -eq $faultFailure) { throw }
                throw [AggregateException]::new(
                    'Fault run and sanitized failure-status collection both failed.',
                    [Exception[]]@($faultFailure, $_.Exception))
            }
        } finally {
            if ($chaosStarted) {
                [void](Invoke-Checked powershell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher, '-Action', 'ChaosEnd'))
                $chaosStarted = $false
            }
        }
    }
} catch {
    $runFailure = $_.Exception
    try {
        $failureBindingExists = Test-Path -LiteralPath (
            Join-Path $Secrets 'resend-chaos.binding.json')
        $runningChaos = @(& docker ps `
            --filter 'label=com.xpoint.survival.resend-chaos=development-only' `
            --filter 'status=running' --format '{{.Names}}')
        if ($failureBindingExists -and $runningChaos.Count -eq 1) {
            $failedStatusOutput = @(& powershell -NoProfile -ExecutionPolicy Bypass `
                -File $Launcher -Action ChaosStatus)
            $failedStatus = ($failedStatusOutput | Where-Object {
                    $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"'
                } | Select-Object -Last 1) | ConvertFrom-Json
            $runFailure = [InvalidOperationException]::new(
                ('Chaos run failed with sanitized proxy counters: requests={0}, attempts={1}, dispatches={2}, successes={3}, injections={4}.' -f
                    $failedStatus.requestCount,
                    $failedStatus.operationAttemptCount,
                    $failedStatus.operationUpstreamDispatchCount,
                    $failedStatus.operationUpstreamSuccessCount,
                    $failedStatus.injectedFaultCount),
                $runFailure)
        }
    } catch {
        $runFailure = [AggregateException]::new(
            'Chaos run and sanitized failure-status collection both failed.',
            [Exception[]]@($runFailure, $_.Exception))
    }
} finally {
    $cleanupFailures = [Collections.Generic.List[Exception]]::new()
    if ($null -ne $runFailure) { $cleanupFailures.Add($runFailure) }
    try {
        if ($chaosStarted) {
            [void](Invoke-Checked powershell @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher,
                '-Action', 'ChaosEnd'))
            $chaosStarted = $false
        }
    } catch { $cleanupFailures.Add($_.Exception) }
    try {
        Remove-MailboxPrivateStateDirectory `
            -Path $State `
            -ExpectedParent (Join-Path $Root 'artifacts\survival-dev')
        if (Test-Path -LiteralPath $State) {
            throw 'Private ACK state survived terminating final cleanup.'
        }
    } catch { $cleanupFailures.Add($_.Exception) }
    if ($null -ne $sourceLocks) {
        foreach ($sourceLock in $sourceLocks) {
            try { $sourceLock.Dispose() }
            catch { $cleanupFailures.Add($_.Exception) }
        }
    }
    foreach ($temporaryRoot in @($VerificationRoot, $SourceRoot)) {
        if (Test-Path -LiteralPath $temporaryRoot) {
            try { Set-MailboxTreeWritable $temporaryRoot }
            catch { $cleanupFailures.Add($_.Exception) }
        }
    }
    if (Test-Path -LiteralPath $BuildWork) {
        try {
            Set-MailboxTreeWritable $BuildWork
            Remove-Item -LiteralPath $BuildWork -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $BuildWork) {
                throw 'Isolated resend-chaos build directory survived final cleanup.'
            }
        } catch { $cleanupFailures.Add($_.Exception) }
    }
    try {
        $finalStatusOutput = Invoke-Checked powershell @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $Launcher,
            '-Action', 'ChaosStatus')
        $finalStatus = ($finalStatusOutput | Where-Object {
                $_ -match '^\{"schema":"deep-survival-resend-chaos-status\.v2"'
            } | Select-Object -Last 1) | ConvertFrom-Json
        if ($finalStatus.running -ne $false -or $finalStatus.armed -ne $false -or
            $null -ne $finalStatus.operation -or $null -ne $finalStatus.fault) {
            throw 'Final chaos status is not the exact off baseline.'
        }
    } catch { $cleanupFailures.Add($_.Exception) }
    try {
        Assert-OrdinaryStack
        $proxyCount = @(& docker ps -a `
            --filter 'label=com.xpoint.survival.resend-chaos=development-only' `
            --format '{{.Names}}').Count
        $tokenExists = Test-Path -LiteralPath (Join-Path $Secrets 'resend-chaos.token')
        $bindingExists = Test-Path -LiteralPath (Join-Path $Secrets 'resend-chaos.binding.json')
        if ($proxyCount -ne 0 -or $tokenExists -or $bindingExists -or
            (Test-Path -LiteralPath $State)) {
            throw 'Chaos cleanup left proxy, token, binding, or private ACK state.'
        }
    } catch { $cleanupFailures.Add($_.Exception) }
    if ($cleanupFailures.Count -gt 0) {
        throw [AggregateException]::new(
            'Resend chaos run or fail-closed cleanup did not complete.',
            [Exception[]]$cleanupFailures.ToArray())
    }
}

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
        publicRoutes = @('/api/ingress/v1/frame')
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
        postDurableAckResponseDropRecovered = $true
        ackRetryAfterProcessRestart = $true
        ackInboxEmptyAfterRetry = $true
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
