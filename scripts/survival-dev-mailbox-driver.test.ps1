$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$driver = Join-Path $root 'tools\survival-mailbox-driver\SurvivalMailboxDriver.csproj'
$xnode = [IO.Path]::GetFullPath((Join-Path $root '..\xnode'))
$secrets = Join-Path $root '.secrets\survival-dev'
if (-not (Test-Path -LiteralPath $driver -PathType Leaf) -or
    -not (Test-Path -LiteralPath $xnode -PathType Container) -or
    -not (Test-Path -LiteralPath $secrets -PathType Container)) {
    throw 'The host-only mailbox driver retention test prerequisites are missing.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('deep-mailbox-retention-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
try {
    $authorityEnv = Join-Path $work 'authority.env'
    $clientEnv = Join-Path $work 'client.env'
    $authorityPublic = Join-Path $work 'authority.public.json'
    $privacyRoutesAndroid = Join-Path $work 'privacy-routes.android.v1.json'
    $privacyRoutesWindows = Join-Path $work 'privacy-routes.windows.v1.json'
    $state = Join-Path $work 'state'
    $artifacts = Join-Path $work 'build-artifacts'
    $common = @(
        'run', '--project', $driver, '--artifacts-path', $artifacts,
        "-p:XNodeSource=$xnode", '--')
    $authority = @(& dotnet @common authority `
        '--secrets-dir' $secrets `
        '--output-env' $authorityEnv `
        '--output-client-env' $clientEnv `
        '--output-public' $authorityPublic `
        '--output-privacy-routes-android' $privacyRoutesAndroid `
        '--output-privacy-routes-windows' $privacyRoutesWindows `
        '--privacy-entry-host' '127.0.0.1' `
        '--coordinator-url' 'http://127.0.0.1:41801')
    if ($LASTEXITCODE -ne 0) { throw 'Host-only authority generation failed.' }
    $resultLines = @(& dotnet @common retention-gc `
        '--secrets-dir' $secrets `
        '--authority-public' $authorityPublic `
        '--state-dir' $state `
        '--coordinator-url' 'http://127.0.0.1:41801')
    if ($LASTEXITCODE -ne 0) { throw 'Host-only retention-gc execution failed.' }
    $json = @($resultLines | Where-Object { $_ -match '^\{"schemaVersion":1,' })
    if ($json.Count -ne 1) { throw 'Host-only retention-gc emitted no unique sanitized JSON result.' }
    $result = $json[0] | ConvertFrom-Json
    if ($result.phase -ne 'retention-gc' -or $result.passed -ne $true -or
        $result.details.authorityBound -ne 'epoch-expiry-plus-fixed-retention' -or
        $result.details.retainedAtBoundary -ne $true -or
        $result.details.collectedAfterBoundary -ne 1 -or
        $result.details.replayOutcomeCoordinated -ne $true -or
        $result.details.capacityRecovered -ne $true) {
        throw 'Host-only retention-gc did not prove the coordinated public runtime lifecycle.'
    }
    Write-Output 'survival-dev mailbox driver retention contract: PASS'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
