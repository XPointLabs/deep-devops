$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory '..'))
$launcher = Join-Path $scriptDirectory 'first-release-local.ps1'
$example = Join-Path $repositoryRoot '.env.first-release.local.example'
$authorityPreflight = Join-Path $scriptDirectory 'first-release-local-authority-preflight.ps1'

$previousErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$output = & powershell -NoProfile -ExecutionPolicy Bypass -File $launcher `
    -Action Config -EnvFile $example 2>&1
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $previousErrorActionPreference

if ($exitCode -eq 0) {
    throw 'The launcher accepted the placeholder environment example.'
}
if (($output | Out-String) -notmatch 'required-value markers') {
    throw 'The launcher did not fail with the bounded placeholder diagnostic.'
}

[void][scriptblock]::Create((Get-Content -Raw -LiteralPath $launcher))
[void][scriptblock]::Create((Get-Content -Raw -LiteralPath $authorityPreflight))
$launcherSource = Get-Content -Raw -LiteralPath $launcher
$authorityPreflightSource = Get-Content -Raw -LiteralPath $authorityPreflight
if ($launcherSource -notmatch 'ProductionCapabilityAvailable\\s\*=>\\s\*false' -or
    $launcherSource -notmatch 'IContactResolveTrustedTimeContextSource' -or
    $launcherSource -notmatch 'IContactResolveOneUseRequestLedger' -or
    $launcherSource -notmatch 'IContactResolveDtt1WitnessCustody' -or
    $launcherSource -notmatch 'DEV trust and synthetic artifacts are forbidden') {
    throw 'The launcher is missing an exact fail-closed runtime/authority preflight.'
}
foreach ($required in @(
    'IXPointNetworkBootstrapRootSigner',
    'ADH1', 'ADC1', 'XVP1', 'XNV1', 'XNH1', 'XND1', 'PMT2',
    'only nonce-bound DTT1/ADP1')) {
    if ($authorityPreflightSource.IndexOf($required, [StringComparison]::Ordinal) -lt 0) {
        throw "The exact production-authority preflight is missing: $required"
    }
}
if ($launcherSource -notmatch "'ProvisionTime'" -or
    $launcherSource -notmatch "'AuthorPackage'" -or
    $launcherSource -notmatch "'contact-resolve-authority'") {
    throw 'The launcher does not expose the Registry production operator command safely.'
}
if ($launcherSource -notmatch "'build', 'registry', 'xnode-1'" -or
    $launcherSource -notmatch "'up', '-d', '--no-build'") {
    throw 'The launcher must build the shared XNode image exactly once before Up.'
}
Write-Output 'First-release local PowerShell launcher checks passed.'
