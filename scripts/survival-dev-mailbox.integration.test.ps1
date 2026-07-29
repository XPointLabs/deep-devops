[CmdletBinding()]
param(
    [string]$XNodeRepository,
    [string]$EvidencePath,
    [string]$BindHost = '127.0.0.1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if ([string]::IsNullOrWhiteSpace($XNodeRepository)) {
    $XNodeRepository = Join-Path $Root '..\xnode'
}
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\p10c-mailbox-integration.json'
}
$XNodeRepository = [IO.Path]::GetFullPath($XNodeRepository)
$EvidencePath = [IO.Path]::GetFullPath($EvidencePath)
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$expectedCommit = '37a8412653daac89dda967ae8bd81ab29cf8aa93'

function Invoke-Checked([string]$File, [string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE." }
}

function Get-HttpStatus([string]$Uri) {
    try {
        return (Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method Post -TimeoutSec 5).StatusCode
    } catch {
        $response = $_.Exception.Response
        if ($null -ne $response) { return [int]$response.StatusCode }
        throw
    }
}

$commit = (& git -C $XNodeRepository rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -ne $expectedCommit) {
    throw 'P10C integration evidence requires the accepted clean XNode source revision.'
}
if ((& git -C $XNodeRepository status --porcelain=v1 --untracked-files=all)) {
    throw 'P10C integration evidence requires a clean XNode source checkout.'
}

# These exact source-integrated cases cover canonical PRQ2 Store/Tombstone durability,
# 2-of-2 quorum, restart replay, startup corruption rejection, and one-peer loss.
Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.Tests\XNode.Tests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxTests', '--logger', 'console;verbosity=minimal')
Invoke-Checked dotnet @('test', (Join-Path $XNodeRepository 'tests\XNode.IntegrationTests\XNode.IntegrationTests.csproj'), '--no-restore', '--filter', 'FullyQualifiedName~ReplicatedMailboxIntegrationTests', '--logger', 'console;verbosity=minimal')

Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'ps')
$nodes = @()
foreach ($index in 1..6) {
    $port = 41800 + $index
    $ready = Invoke-RestMethod -Uri "http://${BindHost}:$port/health/ready" -TimeoutSec 5
    $status = Invoke-RestMethod -Uri "http://${BindHost}:$port/status" -TimeoutSec 5
    if ($ready.ready -ne $true -or $ready.mailboxPeer -ne 'ready' -or $status.mailbox.enabled -ne $true -or $status.mailbox.peerRuntime -ne 'ready') {
        throw "xnode-$index did not report P10C peer-runtime readiness."
    }
    if ($status.mailboxClient.enabled -ne $false -or $status.mailboxClient.clientIngress -ne 'dormant-unmapped') {
        throw "xnode-$index does not truthfully report dormant public client mailbox ingress."
    }
    if ((Get-HttpStatus "http://${BindHost}:$port/api/peer/mailbox/v2/store") -ne 404) {
        throw "xnode-$index exposed a peer mailbox route on the public listener."
    }
    $nodes += [pscustomobject]@{ node = "xnode-$index"; ready = $true; peerRuntime = $status.mailbox.peerRuntime; clientIngress = $status.mailboxClient.clientIngress }
}

$evidence = [pscustomobject]@{
    schemaVersion = 1
    generatedAt = [DateTimeOffset]::UtcNow
    xnodeCommit = $commit
    passed = $true
    replicaContract = [pscustomobject]@{
        quorum = '2-of-2'
        store = 'source-integrated-tested'
        tombstone = 'source-integrated-tested'
        restartReplay = 'source-integrated-tested'
        corruptionReadiness = 'source-integrated-tested'
        oneNodeLoss = 'source-integrated-tested-partial-never-quorum'
    }
    runtime = $nodes
    publicClientMailbox = 'dormant-unmapped-reject-all'
    rollback = 'preserve xnode-N-state volumes; recreate only xnode services from the prior local image or DevOps commit; never reset corrupt state to claim recovery'
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
[IO.File]::WriteAllText($EvidencePath, (($evidence | ConvertTo-Json -Depth 6) + "`n"), [Text.UTF8Encoding]::new($false))
Write-Output "P10C mailbox integration evidence: $EvidencePath"
