[CmdletBinding()]
param(
    [string]$ClientRepository,
    [string]$SharedRepository,
    [string]$EvidencePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$EnvironmentPath = Join-Path $Root 'artifacts\survival-dev\client.windows.env'
if ([string]::IsNullOrWhiteSpace($ClientRepository)) {
    $ClientRepository = Join-Path $Root '..\deep-client-maui'
}
if ([string]::IsNullOrWhiteSpace($SharedRepository)) {
    $SharedRepository = Join-Path $Root '..\deep-client-shared'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\six-node-chaos.json'
}
$ClientRepository = [IO.Path]::GetFullPath($ClientRepository)
$SharedRepository = [IO.Path]::GetFullPath($SharedRepository)
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$SharedTestProject = Join-Path $SharedRepository 'tests\Deep.Client.Shared.Tests\Deep.Client.Shared.Tests.csproj'
$Nodes = 1..6 | ForEach-Object { "xnode-$_" }
$contractResults = [Collections.Generic.List[object]]::new()
$recoveryResults = [Collections.Generic.List[object]]::new()

function Invoke-Checked([string]$File,[string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE."
    }
}

function Get-Commit([string]$Repository) {
    $commit = & git -C $Repository rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($commit)) {
        throw "Unable to resolve source commit for $Repository."
    }
    return $commit.Trim()
}

function Wait-Node([int]$Index) {
    $uri = "http://127.0.0.1:$([int](41800 + $Index))/health/ready"
    foreach ($attempt in 1..60) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for xnode-$Index."
}

function Assert-NodeUnavailable([int]$Index) {
    $uri = "http://127.0.0.1:$([int](41800 + $Index))/health/ready"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 2
        throw "xnode-$Index unexpectedly returned HTTP $($response.StatusCode) after stop."
    } catch [System.Net.WebException] {
        return
    } catch [System.Net.Http.HttpRequestException] {
        return
    } catch {
        if ($_.Exception.Message -match 'Unable to connect|connection|actively refused|No connection') { return }
        throw
    }
}

function Invoke-ContractEvidence([string]$Name, [string]$TestName, [string]$Claim, [string]$Limitation) {
    $startedAt = [DateTimeOffset]::UtcNow
    Invoke-Checked dotnet @(
        'test', $SharedTestProject, '--no-restore',
        '--filter', "FullyQualifiedName=$TestName",
        '--logger', 'console;verbosity=minimal')
    $contractResults.Add([pscustomobject]@{
        name = $Name
        kind = 'source-contract'
        test = $TestName
        passed = $true
        claim = $Claim
        limitation = $Limitation
        startedAt = $startedAt
        completedAt = [DateTimeOffset]::UtcNow
    })
}

if (-not (Test-Path -LiteralPath $EnvironmentPath -PathType Leaf)) {
    throw "Missing $EnvironmentPath. Start the survival stack first."
}
if (-not (Test-Path -LiteralPath $SharedTestProject -PathType Leaf)) {
    throw "Missing shared transport test project: $SharedTestProject"
}

foreach ($line in Get-Content -LiteralPath $EnvironmentPath) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
    $parts = $line.Split('=', 2)
    if ($parts.Count -ne 2) { throw "Invalid client environment line: $line" }
    Set-Item -Path "Env:$($parts[0])" -Value $parts[1]
}
$routerEntries = @($env:XNODE_URLS.Split(';', [StringSplitOptions]::RemoveEmptyEntries))
if ($routerEntries.Count -ne 6) { throw 'Chaos rehearsal requires exactly six pinned XNODE_URLS entries.' }

# These tests instrument the client transport itself.  They are deliberately not
# presented as a live replicated-storage exercise: all development XNodes share
# one storage service and therefore cannot prove per-node durability or dedupe.
Invoke-ContractEvidence `
    'pre-dispatch-ingress-fallback' `
    'Deep.Client.Shared.Tests.Services.SessionTransportTests.RoutedStorage_StoreRouteAcquisitionFailureUsesFallbackBeforeSingleDispatch' `
    'A classified route-acquisition failure may use the next pinned ingress before any onion store dispatch.' `
    'The injected failure is a transport contract test; this does not prove an arbitrary stopped node was the selected ingress in a live message flow.'
Invoke-ContractEvidence `
    'retrieve-postdispatch-fallback' `
    'Deep.Client.Shared.Tests.Services.SessionTransportTests.RoutedStorage_RetrievePostDispatchTransportFailureRetriesOnceOnStrictlyDisjointRoute' `
    'A retrieve transport failure is retried once using a route that excludes the first route nodes.' `
    'Development-only privacy-degraded behavior: the second route request carries excluded router IDs. It is not a production anonymity claim.'
Invoke-ContractEvidence `
    'store-ambiguous-outcome-no-redispatch' `
    'Deep.Client.Shared.Tests.Services.SessionTransportTests.RoutedStorage_StoreCommittedButResponseTransportFailsDoesNotRedispatch' `
    'After an ambiguous store dispatch the client returns an outcome-unknown error and performs exactly one onion dispatch.' `
    'This proves client-layer no-redispatch only; it neither proves storage replication nor server-side cross-node deduplication.'
Invoke-ContractEvidence `
    'store-signed-peer-failure-no-redispatch' `
    'Deep.Client.Shared.Tests.Services.SessionTransportTests.RoutedStorage_StoreSignedPeerTransportFailureDoesNotRedispatch' `
    'A signed peer transport failure on a store is outcome-unknown rather than a second store attempt.' `
    'This proves client-layer no-redispatch only; it neither proves storage replication nor server-side cross-node deduplication.'

Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'ps')
Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', '127.0.0.1')

try {
    foreach ($index in 1..6) {
        $node = "xnode-$index"
        $startedAt = [DateTimeOffset]::UtcNow
        Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'stop', $node)
        try {
            Assert-NodeUnavailable $index
        } finally {
            Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'up', '-d', '--wait', $node)
            Wait-Node $index
        }
        $recoveryResults.Add([pscustomobject]@{
            stoppedNode = $node
            passed = $true
            claim = 'The stopped development XNode became unavailable and returned ready after container recovery.'
            limitation = 'This only proves local container availability recovery. It does not prove client write continuity through an arbitrary failed intermediate relay or persisted relay state without bootstrap.'
            startedAt = $startedAt
            completedAt = [DateTimeOffset]::UtcNow
        })
    }
} finally {
    Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'up', '-d', '--wait')
}

Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', '127.0.0.1')
$evidence = [pscustomobject]@{
    schemaVersion = 2
    generatedAt = [DateTimeOffset]::UtcNow
    source = [pscustomobject]@{
        deepDevopsCommit = Get-Commit $Root
        deepClientMauiCommit = Get-Commit $ClientRepository
        deepClientSharedCommit = Get-Commit $SharedRepository
    }
    topology = 'six-pinned-xnodes-shared-development-storage'
    passed = ($contractResults.Count -eq 4 -and $recoveryResults.Count -eq 6)
    claims = [pscustomobject]@{
        productionDiscoveryClaimed = $false
        replicatedStorageClaimed = $false
        arbitraryIntermediateWriteContinuityClaimed = $false
        crossNodeDeduplicationClaimed = $false
        preDispatchIngressFallback = 'source-contract-tested'
        retrievePostDispatchFallback = 'source-contract-tested-privacy-degraded-development-only'
        ambiguousStoreNoRedispatch = 'source-contract-tested-client-layer-only'
        containerRecovery = 'live-container-availability-tested'
    }
    noGo = @(
        'No claim of arbitrary intermediate-relay write continuity.',
        'No claim of replicated storage or cross-node deduplication: all six XNodes use one development storage backend.',
        'No claim of production anonymity or dynamic membership discovery.',
        'No claim that restored contacts persisted without bootstrap reseeding.'
    )
    sourceContractCases = $contractResults
    liveContainerRecoveryCases = $recoveryResults
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
[IO.File]::WriteAllText(
    $EvidencePath,
    ($evidence | ConvertTo-Json -Depth 8) + "`n",
    [Text.UTF8Encoding]::new($false))
Write-Output "Six-node bounded chaos evidence: $EvidencePath"
