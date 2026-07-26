[CmdletBinding()]
param(
    [string]$ClientRepository,
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
if ([string]::IsNullOrWhiteSpace($EvidencePath)) {
    $EvidencePath = Join-Path $Root 'artifacts\survival-dev\six-node-chaos.json'
}
$ClientRepository = [IO.Path]::GetFullPath($ClientRepository)
$TestProject = Join-Path $ClientRepository 'tests\Deep.Client.Maui.ViewModels.Tests\Deep.Client.Maui.ViewModels.Tests.csproj'
$Nodes = 1..6 | ForEach-Object { "xnode-$_" }
$results = [Collections.Generic.List[object]]::new()

function Invoke-Checked([string]$File,[string[]]$Arguments) {
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$File failed with exit code $LASTEXITCODE."
    }
}

function Wait-Node([int]$Index) {
    $uri = "http://127.0.0.1:$([int](41800 + $Index))/api/network/contact"
    foreach ($attempt in 1..60) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw "Timed out waiting for xnode-$Index."
}

if (-not (Test-Path -LiteralPath $EnvironmentPath -PathType Leaf)) {
    throw "Missing $EnvironmentPath. Start the survival stack first."
}
if (-not (Test-Path -LiteralPath $TestProject -PathType Leaf)) {
    throw "Missing client live acceptance project: $TestProject"
}

foreach ($line in Get-Content -LiteralPath $EnvironmentPath) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
    $parts = $line.Split('=', 2)
    if ($parts.Count -ne 2) { throw "Invalid client environment line: $line" }
    Set-Item -Path "Env:$($parts[0])" -Value $parts[1]
}
$routerEntries = @($env:XNODE_URLS.Split(';', [StringSplitOptions]::RemoveEmptyEntries))
if ($routerEntries.Count -ne 6) { throw 'Chaos rehearsal requires exactly six pinned XNODE_URLS entries.' }
$env:DEEP_STRICT_LIVE = '1'
Remove-Item Env:DEEP_STORAGE_URL -ErrorAction SilentlyContinue

Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'ps')
Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', '127.0.0.1')

try {
    foreach ($index in 1..6) {
        $node = "xnode-$index"
        $startedAt = [DateTimeOffset]::UtcNow
        Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'stop', $node)
        try {
            Invoke-Checked dotnet @(
                'test', $TestProject, '--no-restore',
                '--filter', 'FullyQualifiedName~ClientLiveAcceptanceTests',
                '--logger', 'console;verbosity=minimal')
            $results.Add([pscustomobject]@{
                stoppedNode = $node
                passed = $true
                startedAt = $startedAt
                completedAt = [DateTimeOffset]::UtcNow
                duplicateAssertion = 'ClientLiveAcceptanceTests requires a single received direct message and group message.'
            })
        } finally {
            Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'up', '-d', '--wait', $node)
            Wait-Node $index
        }
    }
} finally {
    Invoke-Checked docker @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath, 'up', '-d', '--wait')
}

Invoke-Checked node @((Join-Path $PSScriptRoot 'survival-dev-verify.mjs'), '--host', '127.0.0.1')
$evidence = [pscustomobject]@{
    schemaVersion = 1
    generatedAt = [DateTimeOffset]::UtcNow
    topology = 'six-pinned-xnodes-two-disjoint-three-hop-attempts'
    productionDiscoveryClaimed = $false
    passed = $results.Count -eq 6 -and @($results | Where-Object { -not $_.passed }).Count -eq 0
    cases = $results
}
[void][IO.Directory]::CreateDirectory((Split-Path $EvidencePath -Parent))
[IO.File]::WriteAllText(
    [IO.Path]::GetFullPath($EvidencePath),
    ($evidence | ConvertTo-Json -Depth 6) + "`n",
    [Text.UTF8Encoding]::new($false))
Write-Output "Six-node chaos evidence: $([IO.Path]::GetFullPath($EvidencePath))"
