[CmdletBinding()]
param(
    [string]$XNodeRepository,
    [string]$EvidencePath,
    [string]$BindHost = '192.168.1.44'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ([string]::IsNullOrWhiteSpace($XNodeRepository)) { $XNodeRepository = Join-Path $Root '..\xnode' }
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\p10e-mailbox-integration.json'
}
$XNodeRepository = [IO.Path]::GetFullPath($XNodeRepository)
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$Launcher = Join-Path $PSScriptRoot 'survival-dev.ps1'
$Project = 'deep-survival-dev'
$expectedCommit = 'f2bdb1178a52b6258f5664e72629a5659b44e518'
$expectedManifest = '0ae0a297f1e7a6b494198c52964a46727e2c802d828335ba702313bc810868e8'
$base = @('compose', '-p', $Project, '-f', $ComposePath)
$nodes = 1..6 | ForEach-Object { "xnode-$_" }

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Invoke-Docker([string[]]$Arguments) {
    Invoke-Checked docker ($base + $Arguments)
}

function Invoke-Driver([string]$Phase, [string]$RunId = '') {
    $arguments = @(
        '--profile', 'mailbox-rehearsal', 'run', '--rm', '--no-deps',
        'mailbox-driver', $Phase,
        '--state-dir', '/state/driver',
        '--client-url', 'http://xnode-1:8080',
        '--coordinator-url', "http://${BindHost}:41801"
    )
    if (-not [Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($BindHost))) {
        $arguments += '--require-non-loopback-coordinator'
    }
    if (-not [string]::IsNullOrWhiteSpace($RunId)) { $arguments += @('--run-id', $RunId) }
    $output = @(& docker @base @arguments)
    if ($LASTEXITCODE -ne 0) { throw "Live mailbox driver phase '$Phase' failed." }
    $jsonLines = @($output | Where-Object { $_ -match '^\{"schemaVersion":1,' })
    if ($jsonLines.Count -ne 1) { throw "Live mailbox driver phase '$Phase' emitted no unique sanitized result." }
    $result = $jsonLines[0] | ConvertFrom-Json
    if ($result.passed -ne $true -or $result.phase -notmatch '^(reset|retention-gc|store|replay|selected-peer-loss|selected-peer-retry|tombstone|client-lifecycle|client-selected-peer-loss|client-selected-peer-retry)$') {
        throw "Live mailbox driver phase '$Phase' did not pass."
    }
    return $result
}

function Get-HttpStatus([string]$Uri) {
    try {
        return (Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -TimeoutSec 5).StatusCode
    } catch {
        if ($null -ne $_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        throw
    }
}

function Assert-Runtime() {
    $runtime = @()
    foreach ($index in 1..6) {
        $port = 41800 + $index
        $ready = Invoke-RestMethod -Uri "http://${BindHost}:$port/health/ready" -TimeoutSec 5
        $status = Invoke-RestMethod -Uri "http://${BindHost}:$port/status" -TimeoutSec 5
        if ($ready.ready -ne $true -or $ready.mailboxPeer -ne 'ready' -or $status.mailbox.peerRuntime -ne 'ready') {
            throw "xnode-$index did not report peer-runtime readiness."
        }
        if ($index -eq 1) {
            if ($ready.mailboxClient.reason -ne 'ready' -or
                $status.mailboxClient.enabled -ne $true -or
                $status.mailboxClient.clientRoutesMapped -ne $true -or
                $status.mailboxClient.clientIngress -ne 'canonical-mst1-mrt1-mak1') {
                throw 'xnode-1 does not truthfully report ready canonical client ingress.'
            }
            $clientIngress = 'canonical-mst1-mrt1-mak1'
        } else {
            if ($status.mailboxClient.enabled -ne $false -or
                $status.mailboxClient.clientIngress -ne 'dormant-unmapped') {
                throw "xnode-$index does not truthfully report dormant-unmapped client ingress."
            }
            $clientIngress = 'dormant-unmapped'
        }
        if ((Get-HttpStatus "http://${BindHost}:$port/api/peer/mailbox/v2/store") -ne 404) {
            throw "xnode-$index exposed its peer mailbox route on the public listener."
        }
        $runtime += [pscustomobject]@{
            node = "xnode-$index"
            ready = $true
            peerRuntime = 'ready'
            clientIngress = $clientIngress
        }
    }
    return $runtime
}

function Get-ImageBinding() {
    $imageId = (& docker image inspect deep-survival/xnode:dev --format '{{.Id}}').Trim()
    $revision = (& docker image inspect deep-survival/xnode:dev --format '{{index .Config.Labels "org.opencontainers.image.revision"}}').Trim()
    $manifest = (& docker image inspect deep-survival/xnode:dev --format '{{index .Config.Labels "com.xpoint.source-context.manifest-sha256"}}').Trim()
    if ($LASTEXITCODE -ne 0 -or $revision -ne $expectedCommit -or $manifest -ne $expectedManifest -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
        throw 'The live XNode image is not bound to the exact accepted source revision and context manifest.'
    }
    foreach ($node in $nodes) {
        $container = (& docker @base ps -q $node).Trim()
        $containerImage = (& docker inspect $container --format '{{.Image}}').Trim()
        if ($LASTEXITCODE -ne 0 -or $containerImage -ne $imageId) {
            throw "$node is not running the exact shared accepted XNode image."
        }
    }
    return [pscustomobject]@{ imageId = $imageId; revision = $revision; sourceContextManifestSha256 = $manifest; allSixExact = $true }
}

$commit = (& git -C $XNodeRepository rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -ne $expectedCommit) {
    throw 'P10E live rehearsal requires the accepted XNode revision.'
}
if ((& git -C $XNodeRepository status --porcelain=v1 --untracked-files=all)) {
    throw 'P10E live rehearsal requires a clean XNode source checkout.'
}
$bindAddress = [Net.IPAddress]::Parse($BindHost)
if ($bindAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $bindAddress.ToString() -cne $BindHost -or
    $bindAddress.Equals([Net.IPAddress]::Any)) {
    throw 'BindHost must be an exact IPv4 address.'
}

$env:SURVIVAL_BIND_HOST = $BindHost
$env:SURVIVAL_XNODE_PATH = $XNodeRepository
$phases = @()
$runId = [Guid]::NewGuid().ToString('N')
try {
    # Retain source regressions, then build both consumers from the same exact
    # filtered context. The runtime proof below is independent and live.
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~DurableMailboxCapabilityReplayJournalTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxIntegrationTests', '--logger', 'console;verbosity=minimal')
    Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~MailboxClientActivatedEndToEndTests', '--logger', 'console;verbosity=minimal')
    & $Launcher -Action Build -Service @('xnode-1', 'mailbox-driver')

    # Recreate, never reset, each peer so all six receive the real authority
    # and exact labelled image while preserving their named state volumes.
    Invoke-Docker (@('up', '-d', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '180') + $nodes)
    Invoke-Docker @('--profile', 'mailbox-rehearsal', 'up', '--no-deps', 'mailbox-driver-state-init')
    $phases += Invoke-Driver 'reset'
    $phases += Invoke-Driver 'retention-gc'
    $phases += Invoke-Driver 'client-lifecycle' $runId
    $phases += Invoke-Driver 'store' $runId

    # Exact recipient MRR2 and sender MQR3 must survive recipient recreation.
    Invoke-Docker @('up', '-d', '--no-deps', '--force-recreate', '--wait', '--wait-timeout', '180', 'xnode-2')
    $phases += Invoke-Driver 'replay'

    # Public client Store must never claim quorum while its selected xnode-2
    # peer is unavailable. Retry the exact persisted MST1 after recovery.
    Invoke-Docker @('stop', '-t', '10', 'xnode-2')
    $phases += Invoke-Driver 'client-loss' $runId
    Invoke-Docker @('start', 'xnode-2')
    Invoke-Docker @('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180', 'xnode-2')
    $phases += Invoke-Driver 'client-retry-loss'

    # Loss is the selected recipient, so local durability is explicitly partial
    # and cannot be reported as quorum. Retry the same PRQ2 after recovery.
    Invoke-Docker @('stop', '-t', '10', 'xnode-3')
    $phases += Invoke-Driver 'loss' $runId
    Invoke-Docker @('start', 'xnode-3')
    Invoke-Docker @('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180', 'xnode-3')
    $phases += Invoke-Driver 'retry-loss'
    $phases += Invoke-Driver 'tombstone'

    $runtime = Assert-Runtime
    $binding = Get-ImageBinding
    Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', $BindHost)

    $evidence = [pscustomobject]@{
        schemaVersion = 2
        generatedAt = [DateTimeOffset]::UtcNow
        scope = 'development-only-live-docker-public-client-and-peer-rehearsal'
        passed = $true
        imageBinding = $binding
        protocol = 'P10E/MCP2/MAU2/MST1/MRT1/MRP1/MAK1/MAR1/MIP1/RIP1/PRQ2/MRR2/MQR3'
        phases = $phases
        runtime = $runtime
        assertions = [pscustomobject]@{
            realPeerNetwork = $true
            publicStoreRetrieveAck = $true
            publicStoreExactReplay = $true
            publicSelectedPeerLossNeverQuorum = $true
            publicSelectedPeerRestartExactRetryQuorum = $true
            boundedReplayRetirementGcSourceRegression = $true
            boundedReplayRetirementGcDriver = $true
            storeTwoOfTwo = $true
            exactReplayAfterRecipientRecreate = $true
            selectedPeerLossNeverQuorum = $true
            selectedPeerRestartRetryQuorum = $true
            tombstoneTwoOfTwoAndReplay = $true
            namedVolumesPreserved = $true
            publicClientMailbox = 'xnode-1-bounded-development-fixture-only'
        }
        limitations = 'The public client ingress and issuer are deterministic DEV-LOCAL-ONLY fixtures; this is not production authority, production durability, or a production-readiness claim.'
    }
    [void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
    [IO.File]::WriteAllText($EvidencePath, (($evidence | ConvertTo-Json -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Output "Live P10E mailbox rehearsal evidence: $EvidencePath"
}
finally {
    # Restore the selected peer and converge all XNodes to healthy without
    # deleting or recreating any named state volume.
    & docker @base start xnode-2 xnode-3 2>$null | Out-Null
    $restoreArguments = $base + @('up', '-d', '--no-deps', '--wait', '--wait-timeout', '180') + $nodes
    & docker @restoreArguments 2>$null | Out-Null
}
