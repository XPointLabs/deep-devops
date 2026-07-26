[CmdletBinding()]
param(
    [switch]$Build
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
$ComposePath = Join-Path $Root 'docker-compose.survival.dev.yml'
$baseArguments = @('compose', '-p', 'deep-survival-dev', '-f', $ComposePath)
$services = @(
    'membership-artifact-owner-init',
    'membership-artifact-init',
    'membership-fixture'
)

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Docker command failed with exit code $LASTEXITCODE."
    }
}

function Assert-ExitedZero([string]$Service) {
    $containerId = (& docker @baseArguments 'ps' '-q' '-a' $Service)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($containerId)) {
        throw "Missing repeat-test container for $Service."
    }
    $state = (& docker 'inspect' '--format' '{{.State.Status}}|{{.State.ExitCode}}' $containerId)
    if ($LASTEXITCODE -ne 0 -or ([string]$state).Trim() -ne 'exited|0') {
        throw "Repeat-test service $Service did not exit successfully."
    }
}

if ($Build) {
    Invoke-Docker ($baseArguments + @('build', '--no-cache', 'membership-fixture'))
}

$hashes = [Collections.Generic.List[string]]::new()
foreach ($iteration in 1..2) {
    Invoke-Docker ($baseArguments + @('rm', '-sf') + $services)
    Invoke-Docker ($baseArguments + @('up', '--no-build', 'membership-fixture'))
    foreach ($service in $services) {
        Assert-ExitedZero $service
    }

    $logs = (& docker @baseArguments 'logs' '--no-color' '--no-log-prefix' 'membership-fixture')
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read membership fixture logs on iteration $iteration."
    }
    $matches = [regex]::Matches(
        ($logs -join "`n"),
        '(?m)^PublishedArtifactSha256=([0-9a-f]{64})\r?$'
    )
    if ($matches.Count -ne 1 -or ($logs -join "`n") -notmatch 'Generated and Sodium-verified one DEV-LOCAL-ONLY') {
        throw "Iteration $iteration lacks one Sodium-verified artifact result."
    }
    $hash = $matches[0].Groups[1].Value
    Invoke-Docker ($baseArguments + @(
        'run', '--rm', '--no-deps',
        'membership-artifact-init',
        'node',
        '/opt/deep-membership-init/membership-artifact-init.mjs',
        'probe',
        $hash))
    $hashes.Add($hash)
}

Write-Output "Same-volume membership fixture repeat passed: $($hashes -join ', ')"
