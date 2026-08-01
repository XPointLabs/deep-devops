$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script = Get-Content -Raw (Join-Path $PSScriptRoot 'survival-dev-chaos.ps1')
$parameterBlock = (($script -split "`r?`n" | Select-Object -First 6) -join "`n")
if ($parameterBlock -match '\$PSScriptRoot') {
    throw 'Chaos script must resolve default paths after parameter binding.'
}
if ($script -notmatch '\$Root = \[IO\.Path\]::GetFullPath' -or
    $script -notmatch 'if \(\[string\]::IsNullOrWhiteSpace\(\$SharedRepository\)\)' -or
    $script -notmatch 'if \(\[string\]::IsNullOrWhiteSpace\(\$EvidencePath\)\)') {
    throw 'Chaos script does not resolve runtime defaults from its script root.'
}
if ($script -notmatch [regex]::Escape('foreach ($index in 1..6)')) {
    throw 'Chaos script does not iterate the exact six-node recovery set.'
}
if (-not $script.Contains("'stop', `$node") -or
    -not $script.Contains("'up', '-d', '--no-deps', '--wait', `$node")) {
    throw 'Chaos script does not restore each stopped XNode in a finally block.'
}
foreach ($required in @(
    'RoutedStorage_StoreRouteAcquisitionFailureUsesFallbackBeforeSingleDispatch',
    'RoutedStorage_RetrievePostDispatchTransportFailureRetriesOnceOnStrictlyDisjointRoute',
    'RoutedStorage_StoreCommittedButResponseTransportFailsDoesNotRedispatch',
    'RoutedStorage_StoreSignedPeerTransportFailureDoesNotRedispatch',
    'replicatedStorageClaimed = $false',
    'arbitraryIntermediateWriteContinuityClaimed = $false',
    'crossNodeDeduplicationClaimed = $false',
    'source-contract-tested-privacy-degraded-development-only')) {
    if (-not $script.Contains($required)) {
        throw "Chaos script is missing required bounded evidence declaration: $required"
    }
}
if ($script -match 'ClientLiveAcceptanceTests|duplicateAssertion|two-disjoint-three-hop-attempts') {
    throw 'Chaos script retains an unsupported live delivery, deduplication, or disjoint-route claim.'
}
if ($script -match 'catch \[System\.Net\.Http\.HttpRequestException\]') {
    throw 'Chaos script uses a typed HttpRequestException catch that Windows PowerShell 5.1 cannot always resolve.'
}
if ($script -notmatch 'catch \{' -or
    $script -notmatch 'Unable to connect\|connection\|actively refused\|No connection') {
    throw 'Chaos script does not have a PowerShell-version-compatible fail-closed unavailable-node assertion.'
}
if ($script -notmatch '\[System\.Net\.WebExceptionStatus\]::Timeout' -or
    $script -notmatch "'The operation has timed out\.'" -or
    $script -notmatch "'The operation timed out\.'") {
    throw 'Chaos script does not classify Docker proxy timeout as a bounded expected unavailable-node outcome.'
}
if ($script -notmatch 'survival-dev-verify\.mjs' -or
    $script -notmatch 'productionDiscoveryClaimed = \$false') {
    throw 'Chaos evidence does not verify topology recovery or bound production claims.'
}
Write-Output 'survival-dev-chaos contract: PASS'
