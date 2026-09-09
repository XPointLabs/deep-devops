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
    $uri = "http://${RuntimeHost}:$([int](41800 + $Index))/health/ready"
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
    $uri = "http://${RuntimeHost}:$([int](41800 + $Index))/health/ready"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 2
    } catch {
        $messages = @($_.Exception.Message)
        if ($null -ne $_.Exception.InnerException) {
            $messages += $_.Exception.InnerException.Message
        }
        $messages = $messages |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $webException = $_.Exception -as [System.Net.WebException]
        if ($null -ne $webException -and
            $webException.Status -eq [System.Net.WebExceptionStatus]::Timeout) { return }
        if ($messages -contains 'The operation has timed out.' -or
            $messages -contains 'The operation timed out.' -or
            ($messages -join ' ') -match 'Unable to connect|connection|actively refused|No connection') { return }
        throw
    }
    throw "xnode-$Index unexpectedly returned HTTP $($response.StatusCode) after stop."
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
$routerUris = @($routerEntries | ForEach-Object {
    if ($_ -notmatch '(?<url>https?://[^|,;]+)') {
        throw 'Chaos rehearsal XNODE_URLS contains an invalid entry.'
    }
    [Uri]$Matches.url
})
$runtimeHosts = @($routerUris | Select-Object -ExpandProperty Host -Unique)
$runtimeAddress = $null
if ($runtimeHosts.Count -ne 1 -or
    -not ([Net.IPAddress]::TryParse($runtimeHosts[0], [ref]$runtimeAddress)) -or
    $runtimeAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    $runtimeAddress.Equals([Net.IPAddress]::Any)) {
    throw 'Chaos rehearsal requires one exact routable runtime host.'
}
$RuntimeHost = $runtimeHosts[0]
$env:SURVIVAL_BIND_HOST = $RuntimeHost
Remove-Item -LiteralPath $EvidencePath -Force -ErrorAction SilentlyContinue

# These tests instrument the client transport itself.  They are deliberately not
# presented as a live replicated-storage exercise: all development XNodes share
# one storage service and therefore cannot prove per-node durability or dedupe.
Invoke-ContractEvidence `
    'pre-dispatch-ingress-fallback' `
    'Deep.Client.Shared.Tests.Services.PrivacyRoutedMailboxBinaryIngressTests.InitialThreeNodeProfile_AllowsBestEffortFallbackNodeReuse' `
    'The initial three-node profile permits best-effort fallback node reuse; retry remains admissible only after a definitive before-forward rejection, before any mailbox mutation.' `
    'The injected failure is a transport contract test; it does not prove that an arbitrary stopped node was selected in a live message flow or permit fallback after an unknown outcome.'
Invoke-ContractEvidence `
    'postdispatch-outcome-unknown' `
    'Deep.Client.Shared.Tests.Services.PrivacyRoutedMailboxBinaryIngressTests.OutcomeUnknown_NeverUsesFallback' `
    'A post-dispatch transport failure is outcome-unknown and never redispatched on the fallback route.' `
    'This proves client-layer no-redispatch only; storage reconciliation remains a separate survival responsibility.'
Invoke-ContractEvidence `
    'store-ambiguous-outcome-no-redispatch' `
    'Deep.Client.Shared.Tests.Services.PrivacyRoutedMailboxBinaryIngressTests.TerminalOutcomeUnknown_NeverUsesFallback' `
    'After an authenticated ambiguous terminal result the client returns outcome-unknown and performs exactly one privacy-route dispatch.' `
    'This proves client-layer no-redispatch only; it neither proves storage replication nor server-side cross-node deduplication.'
Invoke-ContractEvidence `
    'unauthenticated-reply-no-redispatch' `
    'Deep.Client.Shared.Tests.Services.PrivacyRoutedMailboxBinaryIngressTests.UnauthenticatedReply_IsOutcomeUnknownAndDoesNotFallback' `
    'An unauthenticated reply is outcome-unknown rather than a second privacy-route dispatch.' `
    'This proves client-layer no-redispatch only; it neither proves storage replication nor server-side cross-node deduplication.'

Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'ps')
Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', $RuntimeHost)

try {
    foreach ($index in 1..6) {
        $node = "xnode-$index"
        $startedAt = [DateTimeOffset]::UtcNow
        Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'stop', $node)
        try {
            Assert-NodeUnavailable $index
        } finally {
            Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'up', '-d', '--no-deps', '--wait', $node)
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

Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', $RuntimeHost)
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
        postDispatchNoRedispatch = 'source-contract-tested-client-layer-only'
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
