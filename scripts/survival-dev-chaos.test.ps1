$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script = Get-Content -Raw (Join-Path $PSScriptRoot 'survival-dev-chaos.ps1')
$parameterBlock = (($script -split "`r?`n" | Select-Object -First 5) -join "`n")
if ($parameterBlock -match '\$PSScriptRoot') {
    throw 'Chaos script must resolve default paths after parameter binding.'
}
if ($script -notmatch '\$Root = \[IO\.Path\]::GetFullPath' -or
    $script -notmatch 'if \(\[string\]::IsNullOrWhiteSpace\(\$ClientRepository\)\)' -or
    $script -notmatch 'if \(\[string\]::IsNullOrWhiteSpace\(\$EvidencePath\)\)') {
    throw 'Chaos script does not resolve runtime defaults from its script root.'
}
if ($script -notmatch [regex]::Escape('foreach ($index in 1..6)')) {
    throw 'Chaos script does not iterate the exact six-node set.'
}
if (-not $script.Contains("'stop', `$node") -or
    -not $script.Contains("'up', '-d', '--wait', `$node")) {
    throw 'Chaos script does not restore each stopped XNode in a finally block.'
}
if ($script -notmatch 'ClientLiveAcceptanceTests' -or
    $script -notmatch 'duplicateAssertion') {
    throw 'Chaos script does not run the routed client delivery/dedup acceptance.'
}
if ($script -notmatch 'survival-dev-verify\.mjs' -or
    $script -notmatch 'productionDiscoveryClaimed = \$false') {
    throw 'Chaos evidence does not verify recovery or bound its claim.'
}
Write-Output 'survival-dev-chaos contract: PASS'
